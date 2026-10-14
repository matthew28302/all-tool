# All-Tool — Network Tools Web App

> Bộ công cụ Web cho quản trị viên hệ thống / webmaster: kiểm tra DNS, SSL, Host, tra cứu lịch sử DNS và cấp chứng chỉ SSL miễn phí (ACME).
> Backend: **Python Flask** · Frontend: **HTML + Vanilla JS (main.js)** · Ngôn ngữ UI: **Tiếng Việt**

---

## 📖 Tài liệu cho AI / Developer mới (đọc trước)

Ứng dụng này là **một trang web duy nhất** (`/`) với **hệ thống tab** (sidebar bên trái). Toàn bộ logic nằm ở:

| File | Vai trò |
|---|---|
| `app.py` (~4200 dòng) | Toàn bộ backend Flask — 30 REST endpoints |
| `static/js/main.js` (~4000 dòng) | Toàn bộ frontend logic, gọi API bằng `fetch` |
| `static/css/style.css` (~3800 dòng) | Toàn bộ style (glassmorphism theme) |
| `templates/index.html` | Khung trang + include các tab từ `templates/tabs/*.html` |
| `whois_lookup.py` | Module WHOIS (dùng endpoint `whois.pavietnam.net`) |
| `python_detector.py` | Detect Python interpreter trên máy chủ |
| `acme/` | Lưu trữ order/key/session ACME (SSL miễn phí) |

> ⚠️ **Đã xoá (2026-09-16):** `import-ssl.sh`, endpoint `/api/install-ssl`, toàn bộ JS `installSsl*` — tính năng "Install SSL" cũ không còn trong codebase.

### Cách chạy

```bash
# 1. Tạo venv & cài dependencies
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows (Git Bash)
# .venv/bin/python -m pip install -r requirements.txt     # Linux/macOS

# 2. Chạy server (port mặc định 2803, đổi bằng env PORT)
./run_server.sh          # script tự detect python
# hoặc:
.venv/Scripts/python.exe app.py

# 3. Mở http://localhost:2803
```

Dependencies: `Flask`, `Flask-Cors`, `dnspython`, `cryptography`, `requests`, `acme`, `josepy`.

Deploy Render: xem `render.yaml` (runtime python, start `waitress-serve` — production WSGI, không dùng Flask dev server). Chạy local vẫn dùng `./run_server.sh`.

> 🔐 **Secrets (2026-10-13):** toàn bộ credentials (CIRCL PDNS, ZeroSSL EAB, SSL.com EAB) đã được **xoá khỏi source code**. Thứ tự ưu tiên: biến môi trường → `local_secrets.json` (ngồi cạnh `app.py`, đã gitignore). ⚠️ Các key cũ vẫn còn trong git history — nên **rotate** key CIRCL/ZeroSSL/SSL.com nếu repo từng public.

---

## 🗺️ Sơ đồ kiến trúc & luồng hoạt động

```mermaid
flowchart LR
    subgraph Browser["Trình duyệt"]
        UI["index.html + main.js<br/>(hệ thống tab, defer scripts)"]
    end
    subgraph Flask["Flask Backend (app.py)"]
        DNS["/api/check-dns*<br/>dnspython"]
        SSLCHK["/api/check-ssl<br/>ssl module"]
        HOST["/api/check-host<br/>ip-api.com"]
        HIST["/api/check-dns-history<br/>8 nguồn DNS song song"]
        ACME["/api/ssl-free/*<br/>acme client"]
        STATIC["/static/*<br/>gzip + cache 1 ngày"]
    end
    UI -->|fetch JSON| Flask
    STATIC -->|js/css gzipped| UI
    DNS --> RESOLVERS["25 public DNS resolvers<br/>(Google, Cloudflare, Quad9...)"]
    SSLCHK --> TARGET["Target :443"]
    HOST --> IPAPI["ip-api.com"]
    HIST --> PDNS["Mnemonic / Robtex / OTX / urlscan<br/>HackerTarget / RapidDNS / Subdomain Center"]
    ACME --> CA["Let's Encrypt / ZeroSSL / SSL.com"]
```

### Mô tả từng tab (flow người dùng)

| Tab | Flow | API chính | Trạng thái khi test |
|---|---|---|---|
| **DNS** | Nhập domain → chọn record types (A/AAAA/CNAME/MX/TXT/NS/SOA/CAA) → query **song song 25 resolver** → hiển thị so sánh kết quả + trạng thái propagate | `POST /api/check-dns` (detail), `/api/check-dns-basic` | ✅ Hoạt động tốt (google.com: 23/25 resolver thành công) |
| **Bulk DNS** | Dán danh sách domain → resolve hàng loạt → bảng IP/MX/NS | `POST /api/check-dns-bulk` | ✅ OK (test 2 domain) |
| **DNS History** | Nhập domain → tổng hợp DNS/passive DNS từ **8 nguồn miễn phí không cần API key** → dedupe, gom theo từng mốc thời gian và từng record type (A/AAAA/MX/NS/TXT/CNAME/SUBDOMAIN), mở rộng first/last seen giữa các nguồn | `POST /api/check-dns-history` | ✅ OK |
| **Host Check** | Nhập IP/domain → IP, ASN, ISP, reverse DNS, geolocation (ip-api.com) | `POST /api/check-host` | ✅ OK |
| **WHOIS** | Ưu tiên API `whois.net.vn` cho quốc tế và `.vn`, sau đó RDAP chuẩn, WHOIS port 43 và fallback PA Việt Nam | `POST /api/whois` | ✅ OK |
| **Email Auth** | Quét SPF, DKIM, DMARC, MX; tự động thử selector DKIM theo catalogue của Google Workspace, Microsoft 365, cPanel, iRedMail, MDaemon, Mailcow, Kerio, DirectAdmin và hiển thị Found/Not found từng record | `POST /api/check-email-auth` | ✅ OK |
| **SSL Check** | Nhập domain → lấy cert từ :443 → status, hạn còn lại, issuer, SAN, redirect và toàn bộ chain (Leaf, Chain 1, Chain 2...) | `POST /api/check-ssl` | ✅ OK |
| **SSL Bundle** | Upload ZIP / scan folder / paste PEM → tách & gộp cert+CA bundle, kiểm tra match key | `POST /api/ssl-upload`, `GET /api/ssl-catalog`, `POST /api/check-cert-file` | ✅ Đã fix đường dẫn (env `SSL_CATALOG_DIR`) |
| **SSL Decoder** | 3 mode: Match Checker (cert↔key), Certificate Decoder, CSR Decoder | client-side (forge.js) + `POST /api/check-cert-file` | ✅ UI render OK |
| **SSL Miễn Phí** | Wizard 5 bước: nhập domain/SANs → chọn CA (LE/ZeroSSL/SSL.com) → chọn DNS-01/HTTP-01 → server tạo CSR+order ACME → user thêm TXT record → verify → nhận cert 90 ngày | `POST /api/ssl-free/start` → `/check-challenge` → `/finalize` → `GET /list` | ✅ Đã fix lỗi JS load (bỏ gọi installSsl) |

Tab `Install SSL` và tab `AI Chat` đã bị **xoá hoàn toàn** khỏi codebase (2026-09-16): endpoint `/api/install-ssl`, `/api/ai/*`, toàn bộ JS/CSS liên quan đều đã dọn sạch.

### Danh sách API endpoints

```
GET  /                          Trang chính
GET  /ping                      Health check
GET  /api/python-info           Thông tin Python trên server
GET  /api/system-info           Thông tin hệ thống
POST /api/check-dns             DNS checker chi tiết (25 resolvers)
POST /api/check-dns-basic       DNS checker rút gọn
POST /api/check-dns-bulk        DNS hàng loạt
POST /api/check-dns-history     DNS/passive DNS history (8 nguồn miễn phí)
POST /api/whois                 WHOIS (qua whois.pavietnam.net)
GET  /api/record-types          Danh sách record types
GET  /api/dns-servers           Danh sách DNS servers
POST /api/clear-cache           Xoá cache DNS
POST /api/check-ssl             Kiểm tra chứng chỉ SSL domain
POST /api/check-host            IP/ASN/geolocation của host
POST /api/check-email-auth     SPF/DKIM/DMARC/MX và mail platform fingerprints
POST /api/ssl-catalog           Quét thư mục cert trên server
POST /api/ssl-upload            Upload ZIP/folder cert
GET  /api/ssl-quick-list        Popup "Hiển thị SSL": kind=zip (file .zip trong ~/Downloads) / kind=folder (thư mục trong ~/Desktop/ssl), hỗ trợ ?q=
GET  /api/ssl-quick-zip         Tải bytes 1 file ZIP trong ~/Downloads (?path=...) để phân giải như Upload ZIP
GET  /api/ssl-quick-folder      Đọc text 1 thư mục trong ~/Desktop/ssl (?path=...) để phân giải như Scan Folder
POST /api/check-cert-file       Parse file cert
POST /api/ssl-free/start        Bắt đầu order ACME (tạo CSR, gửi order)
POST /api/ssl-free/check-challenge   Verify DNS-01/HTTP-01
POST /api/ssl-free/finalize     Hoàn tất, tải cert
POST /api/ssl-free/clear-dns-cache  Xoá cache DNS interno
GET  /api/ssl-free/list         Danh sách order đã lưu
GET/DELETE /api/ssl-free/item/<id>   Chi tiết / xoá order
GET  /api/ssl-free/session/<id>/status  Trạng thái session
```

### Biến môi trường

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `PORT` | `2803` | Port server (local) |
| `SSL_CATALOG_DIR` | `~/Desktop/ssl` | Thư mục mặc định cho SSL Bundle scan folder |
| `SSL_DOWNLOADS_DIR` | `~/Downloads` | Thư mục mặc định cho popup "Hiển thị SSL" ở Upload ZIP |
| `DATABASE_URL` | _(rỗng = lưu file local)_ | Postgres để lưu lịch sử Free SSL **khi deploy cloud** (Render/Replit filesystem bị xóa mỗi restart). Replit: Postgres có sẵn (`DATABASE_URL` tự có). Render: tạo Postgres free ở Neon/Supabase rồi set env này. Không set → lưu file `acme/issued_ssl_store.json` như cũ |
| `SSL_CATALOG_ALLOWED_ROOTS` | _(rỗng)_ | Các thư mục gốc được phép quét thêm, cách nhau `;` |
| `WHOIS_CACHE_TTL_SECONDS` | `15` | TTL cache WHOIS |
| `CORS_ORIGINS` | `*` | Giới hạn CORS, ví dụ `https://a.com,https://b.com` |
| `CACHE_TTL_SECONDS` / `CACHE_MAX_ENTRIES` | `300` / `2000` | TTL + giới hạn số entry cache DNS cơ bản |
| `DNS_HISTORY_CACHE_TTL_SECONDS` / `..._MAX_ENTRIES` | `900` / `500` | TTL + giới hạn cache DNS History |
| `CIRCL_PDNS_USER` / `CIRCL_PDNS_PASS` | _(rỗng)_ | Credentials CIRCL Passive DNS |
| `ZEROSSL_EAB_KID` / `ZEROSSL_EAB_HMAC_KEY` | _(rỗng)_ | EAB ZeroSSL (bắt buộc khi chọn provider zerossl) |
| `SSLCOM_EAB_KID` / `SSLCOM_EAB_HMAC_KEY` | _(rỗng)_ | EAB SSL.com (bắt buộc khi chọn provider sslcom) |

---

## 🔍 Kết quả kiểm tra flow (2026-09-16, Windows + Git Bash — sau đợt fix)

| Kiểm thử | Kết quả |
|---|---|
| Load trang: lỗi console/JS | ✅ **0 lỗi** (trước: 2 lỗi) |
| `POST /api/check-dns` cloudflare.com A | ✅ 24/25 resolvers |
| UI tab SSL Check: cloudflare.com | ✅ Hiển thị leaf + full certificate chain |
| UI tab Host Check: 1.1.1.1 | ✅ IP/ASN/ISP/reverse DNS |
| UI tab DNS History: github.io | ✅ **sẽ thay đổi theo nguồn khả dụng**, không còn trộn dữ liệu CT Logs thành TXT |
| Gzip static files | ✅ main.js 194KB → **37.5KB** (giảm 81%) |
| DCL / Load time | ✅ ~700ms (trước: chặn 8.5s do fetch AI models) |
| Transfer size trang | ✅ ~63KB lần đầu (trước: ~320KB) |
| Tab AI Chat đã xoá hoàn toàn | ✅ `/api/ai/*` trả về 404, 0 hàm AI trong JS, 0 console error |

---

## ⚠️ Các vấn đề đã biết (phân tích)

### Đã sửa ✅ (2026-09-16)
1. ✅ **Lỗi JS `installSslLoadCatalog`** — xoá toàn bộ code install-ssl khỏi `main.js` (192 dòng) + backend route `/api/install-ssl` + `import-ssl.sh`.
2. ✅ **404 `theme-premium.css`** — bỏ `<link>` khỏi `index.html`.
3. ✅ **Hardcode `/home/nvpa/Desktop/ssl`** — chuyển sang env `SSL_CATALOG_DIR` (mặc định `~/Desktop/ssl`).
4. ✅ **`mkdtemp(dir='/tmp')`** — dùng tempfile mặc định (không lỗi Windows).
5. ✅ **Chặn 8.5s lúc load** — xoá hoàn toàn tab AI Chat (frontend + backend `/api/ai/*` + CSS), không còn fetch model lúc startup.
6. ✅ **DNS History ít dữ liệu / sai loại** — dùng 8 nguồn DNS/passive DNS miễn phí, bỏ crt.sh vì đây là Certificate Transparency chứ không phải DNS; bổ sung HackerTarget DNS, RapidDNS và Subdomain Center; merge cross-source + dedupe thông minh.
7. ✅ **DNS History khó đọc** — thiết kế lại record item: badge màu theo record type, IP đậm màu xanh, live-dot xanh nhấp nháy cho record còn hiệu lực, filter theo type, limit render 60 records + nút "Xem thêm".
8. ✅ **SSL thiếu certificate chain** — TLS handshake lấy toàn bộ chain server trình bày, parse từng certificate và hiển thị Leaf/Chain 1/Chain 2 với CN, issuer, organization, hạn, serial, signature và SAN.
8. ✅ **Vệ sinh repo** — xoá `__pycache__`, `server.log`, `ssl_history.db`, `proxy.txt`, ~40 script rác (`fix*.py`, `inject_tools*.py`...), backup files; `.gitignore` đầy đủ.
9. ✅ **Hiệu năng** — gzip static (route tùy chỉnh + chống path traversal), `Cache-Control: max-age=86400`, `defer` cho CDN scripts, guard lucide icons.
10. ✅ **Xoá toàn bộ AI Chat** — bỏ ~800 dòng JS (`aiChats`, `loadAIModels`, `sendAIRequest`...), ~900 dòng Python (routes `/api/ai/*`, `AI_TOOLS`, `execute_ai_tool`, `fetch_nvidia_models`...), ~550 dòng CSS (`.ai-*`), imports thừa (`HTTPAdapter`, `Retry`, `stream_with_context`), file `tab_ai.html.bak`.

### Còn tồn tại 🟠
1. **Bug layout mobile (<980px):** `.tab-nav` sticky `height:100vh` đè kín content — chưa sửa do cần thiết kế mobile riêng. Fix nhanh: trong media query mobile đặt `.tab-nav { position: relative; height: auto; max-height: none; }`.
2. **CDN dependencies** (lucide pinned `1.55.0`/jszip/forge/fonts) — offline mất icon & một số tính năng.
3. **Credentials cũ trong git history** — đã xoá khỏi source nhưng cần rotate key CIRCL/ZeroSSL/SSL.com nếu repo từng public.

### Đã tối ưu thêm (2026-10-13) ✅
1. ✅ **Production server:** render.yaml dùng `waitress-serve` thay Flask dev server; thêm `waitress` vào requirements.
2. ✅ **Cache hit không còn `deepcopy`:** DNS History cache lưu JSON đã serialize sẵn (2.6MB response: ~1s → **0.1s**); DNS basic dùng JSON clone.
3. ✅ **Giới hạn cache:** thêm `CACHE_MAX_ENTRIES` / `DNS_HISTORY_CACHE_MAX_ENTRIES` + prune entry cũ nhất — chống phình memory khi chạy lâu.
4. ✅ **Resolver `configure=False`** cho các query đã set nameservers thủ công — bỏ đọc `/etc/resolv.conf` mỗi query (200 lần/request với DNS Check).
5. ✅ **DNSSEC dùng executor global** thay vì tạo ThreadPoolExecutor(2) mới mỗi lần gọi.
6. ✅ **Connection pooling:** `_augment_history_sources` + `_request_public_dns_cache_clear` dùng session dùng chung thay `requests.get`.
7. ✅ **Chống LFI:** `/api/ssl-catalog?path=` và `/api/check-cert-file` chỉ cho đọc trong `SSL_CATALOG_DIR` / roots env / thư mục upload tạm — chặn đọc file hệ thống tuỳ ý.
8. ✅ **CORS cấu hình được** qua env `CORS_ORIGINS` (mặc định vẫn `*`).
9. ✅ **Dọn imports:** bỏ `subprocess`, `ipaddress`, `ec`, `acme_challenges`, alias `cx509` trùng; shebang về dòng 1; log payload cert về `debug`.
10. ✅ **Frontend — main.min.js chạy TRƯỚC CDN libs:** đổi thứ tự script (`main.min.js` đầu, rồi lucide/jszip/forge) + `?v=` cache-busting cho main.min.js → tab tương tác được ngay khi file local tải xong (~100ms) thay vì chờ ~190KB CDN (vài giây trên mạng chậm).
11. ✅ **Lazy-load forge/jszip an toàn:** thêm `ensureForge()` / `ensureJszip()` (tự inject `<script>` khi cần); guard ở tất cả entry point dùng lib (SSL Bundle: file zip, folder, paste, tạo PFX; SSL Decoder: decode cert/key/csr, match key; Free SSL: gói download). Không còn window "main.js chưa chạy vì CDN".
12. ✅ **Google Fonts không render-blocking:** load qua `media="print" onload` + `<noscript>` fallback (giữ `display=swap`).
13. ✅ **`.tab-content` giảm blur 16px → 8px** (raster nhanh hơn; sidebar/hero giữ nguyên).
14. ✅ **HTML response `Cache-Control: no-store`** — luôn lấy template mới nhất sau khi deploy (static assets vẫn cache qua `?v=`).

> Kết quả đo (warm): toàn bộ script về đích ~166ms song song, main.min.js execute đầu tiên; idle 60fps, scroll panel chính 60fps (warm). Đã test luồng SSL Bundle/Decoder/Free SSL với CDN bị gỡ tag (mô phỏng CDN chậm) — decode/paste/lazy-load forge+JSZip đều chạy đúng, console sạch.

---

## 🧭 Gợi ý thứ tự sửa (nếu tiếp tục phát triển)

1. Fix media query mobile `<980px` (bug tương tác nghiêm trọng nhất còn lại).
2. Refactor: tách `app.py` thành blueprint theo nhóm chức năng (dns/ssl/acme), tách `main.js` thành module.
3. Production: waitress/gunicorn + reverse proxy nginx (gzip + cache tại đó).

## License

MIT License - Feel free to use and modify

