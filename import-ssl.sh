#!/bin/bash

# Linux Mint dependencies:
# sudo apt install zenity sshpass dnsutils openssl curl -y
#
# Required local file:
# pass.csv with two columns: IP,Password
#
# Run:
# chmod +x import-ssl.sh
# ./import-ssl.sh

# GUI launchers đôi khi truyền vào PATH rất ngắn và không có /usr/bin.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"

LOG_FILE=$(mktemp)
LOG_PID=""
NO_GUI=false
DOMAIN=""
SERVER_INPUT=""
INPUT_PASS=""
KEY_FILE=""
CERT_FILE=""
BUNDLE_FILE=""

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="${SCRIPT_PATH%/*}"
[ "$SCRIPT_DIR" = "$SCRIPT_PATH" ] && SCRIPT_DIR="."
SCRIPT_DIR=$(cd "$SCRIPT_DIR" && pwd)
PASS_CSV="$SCRIPT_DIR/pass.csv"

while [ $# -gt 0 ]; do
    case "$1" in
        --no-gui)
            NO_GUI=true
            shift
            ;;
        --domain)
            [ $# -ge 2 ] || { echo "ERROR: Missing value for --domain" >&2; exit 2; }
            DOMAIN="$2"
            shift 2
            ;;
        --server)
            [ $# -ge 2 ] || { echo "ERROR: Missing value for --server" >&2; exit 2; }
            SERVER_INPUT="$2"
            shift 2
            ;;
        --password)
            [ $# -ge 2 ] || { echo "ERROR: Missing value for --password" >&2; exit 2; }
            INPUT_PASS="$2"
            shift 2
            ;;
        --key-file)
            [ $# -ge 2 ] || { echo "ERROR: Missing value for --key-file" >&2; exit 2; }
            KEY_FILE="$2"
            shift 2
            ;;
        --cert-file)
            [ $# -ge 2 ] || { echo "ERROR: Missing value for --cert-file" >&2; exit 2; }
            CERT_FILE="$2"
            shift 2
            ;;
        --bundle-file)
            [ $# -ge 2 ] || { echo "ERROR: Missing value for --bundle-file" >&2; exit 2; }
            BUNDLE_FILE="$2"
            shift 2
            ;;
        -h|--help)
            cat <<'USAGE'
Usage:
  ./import-ssl.sh
  ./import-ssl.sh --no-gui --domain example.com --server 1.2.3.4 --password rootpass --key-file /tmp/key.pem --cert-file /tmp/cert.pem --bundle-file /tmp/bundle.pem
USAGE
            exit 0
            ;;
        *)
            echo "ERROR: Unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

show_log_window() {
    if [ "$NO_GUI" = true ]; then
        return 0
    fi
    tail -n +1 -f "$LOG_FILE" | zenity \
        --text-info \
        --title="SSL Installer - Realtime Log" \
        --width=950 \
        --height=600 \
        --font="Monospace 10" &
    LOG_PID=$!
}

log() {
    local msg="[$(date '+%H:%M:%S')] $*"
    if [ "$NO_GUI" = true ]; then
        printf '%s\n' "$msg"
        printf '%s\n' "$msg" >> "$LOG_FILE"
    else
        printf '%s\n' "$msg" | tee -a "$LOG_FILE" >/dev/null
    fi
}

wait_log_close() {
    log "Đóng cửa sổ log để thoát script."
    if [ "$NO_GUI" = true ]; then
        rm -f "$LOG_FILE"
        return 0
    fi
    [ -n "$LOG_PID" ] && wait "$LOG_PID" 2>/dev/null
    rm -f "$LOG_FILE"
}

error_exit() {
    local msg="$1"
    log "ERROR: $msg"
    wait_log_close
    exit 1
}

check_dependencies() {
    local cmd missing=()
    local deps=(sshpass ssh scp dig openssl)

    if [ "$NO_GUI" = false ]; then
        deps+=(zenity)
    fi

    for cmd in "${deps[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done

    if [ ${#missing[@]} -eq 0 ]; then
        return 0
    fi

    local message="Thiếu chương trình: ${missing[*]}\n\nCài bằng lệnh:\nsudo apt install zenity sshpass openssh-client dnsutils openssl -y"

    if [ "$NO_GUI" = true ]; then
        printf '%b\n' "$message" >&2
    elif command -v zenity >/dev/null 2>&1; then
        zenity --error --title="SSL Installer - Thiếu dependency" --text="$message"
    else
        printf '%b\n' "$message" >&2
    fi

    rm -f "$LOG_FILE"
    exit 1
}

clean_target() {
    echo "$1" | tr -d '[:space:]'
}

validate_domain() {
    local d="$1"

    [[ -z "$d" ]] && return 1
    [[ "$d" =~ [[:space:]] ]] && return 1
    [[ ${#d} -gt 253 ]] && return 1
    [[ "$d" != *.* ]] && return 1

    [[ "$d" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]]
}

resolve_server_ip() {
    local s="$1"

    [[ -z "$s" ]] && return 1

    if [[ "$s" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "$s"
        return 0
    fi

    dig +short A "$s" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -n1
}

get_root_password() {
    local server_ip="$1"

    [[ ! -f "$PASS_CSV" ]] && return 2

    while IFS=, read -r csv_ip csv_pass _rest; do
        csv_ip=$(clean_target "$csv_ip")
        csv_pass=${csv_pass%$'\r'}

        [[ -z "$csv_ip" ]] && continue
        [[ "$csv_ip" == "IP" || "$csv_ip" == "ip" ]] && continue

        if [[ "$csv_ip" == "$server_ip" ]]; then
            printf '%s' "$csv_pass"
            return 0
        fi
    done < "$PASS_CSV"

    return 1
}

ssh_root() {
    local server_ip="$1"
    local pass="$2"
    local cmd="$3"

    SSHPASS="$pass" sshpass -e ssh \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=10 \
        -o ServerAliveCountMax=3 \
        root@"$server_ip" \
        "$cmd"
}

detect_control_panel() {
    local server_ip="$1"
    local pass="$2"

    local output ssh_status panel
    output=$(ssh_root "$server_ip" "$pass" '
if [ -x /usr/local/cpanel/bin/whmapi1 ] || command -v whmapi1 >/dev/null 2>&1 || [ -d /usr/local/cpanel ]; then
    echo "__CONTROL_PANEL__:cPanel"
elif [ -x /usr/local/directadmin/directadmin ] || command -v directadmin >/dev/null 2>&1 || [ -d /usr/local/directadmin ]; then
    echo "__CONTROL_PANEL__:DirectAdmin"
else
    echo "__CONTROL_PANEL__:none"
fi
' 2>&1)
    ssh_status=$?

    if [ $ssh_status -ne 0 ]; then
        printf '%s\n' "$output" >>"$LOG_FILE"
        return 2
    fi

    # Chỉ đọc dòng marker vì một số server in banner/MOTD ra stdout khi SSH.
    panel=$(printf '%s\n' "$output" | sed -n 's/^__CONTROL_PANEL__://p' | tail -n1)

    case "$panel" in
        cPanel|DirectAdmin)
            printf '%s\n' "$panel"
            return 0
            ;;
        *)
            printf '%s\n' "$output" >>"$LOG_FILE"
            return 1
            ;;
    esac
}

get_cpanel_domain_owner() {
    local server_ip="$1"
    local pass="$2"
    local domain="$3"

    ssh_root "$server_ip" "$pass" \
        "whmapi1 getdomainowner domain='$domain' | awk '/user:/ {print \$2}'"
}

get_directadmin_domain_owner() {
    local server_ip="$1"
    local pass="$2"
    local domain="$3"

ssh_root "$server_ip" "$pass" "
DOMAIN='$domain'
user=\$(find /usr/local/directadmin/data/users/*/domains -name \"\${DOMAIN}.conf\" 2>/dev/null | awk -F/ '{print \$7}' | head -n1)
if [ -z \"\$user\" ]; then
    user=\$(grep -RslE \"^\${DOMAIN}([=:]|$)\" /usr/local/directadmin/data/users/*/domains/*.pointers 2>/dev/null | awk -F/ '{print \$7}' | head -n1)
fi
echo \"\$user\"
"
}

check_directadmin_domain_alias() {
    local server_ip="$1"
    local pass="$2"
    local owner="$3"
    local domain="$4"

    ssh_root "$server_ip" "$pass" "
OWNER='$owner'
DOMAIN='$domain'
DOMAIN_CONF=\"/usr/local/directadmin/data/users/\$OWNER/domains/\$DOMAIN.conf\"

pointer_match=\$(grep -RhsE \"^\${DOMAIN}([=:]|$)\" /usr/local/directadmin/data/users/*/domains/*.pointers 2>/dev/null | head -n1)

if [ -n \"\$pointer_match\" ]; then
    echo \"ALIAS: \$DOMAIN là DirectAdmin domain pointer/alias (\$pointer_match)\"
    exit 1
fi

if [ -f \"\$DOMAIN_CONF\" ]; then
    echo \"OK: \$DOMAIN có domain config riêng trên DirectAdmin\"
    exit 0
fi

echo \"UNKNOWN: Không thấy domain config riêng cho \$DOMAIN trên DirectAdmin\"
exit 2
"
}

check_cpanel_domain_alias() {
    local server_ip="$1"
    local pass="$2"
    local owner="$3"
    local domain="$4"

    ssh_root "$server_ip" "$pass" "
OWNER='$owner'
DOMAIN='$domain'

if command -v uapi >/dev/null 2>&1; then
    domain_info=\$(uapi --user=\"\$OWNER\" DomainInfo list_domains 2>/dev/null || true)

    if printf '%s\n' \"\$domain_info\" | awk -v d=\"\$DOMAIN\" '
        /^[[:space:]]*parked_domains:/ {section=\"parked\"; next}
        /^[[:space:]]*[a-z_]+:/ {section=\"\"}
        section == \"parked\" && \$0 ~ \"- \" d \"\$\" {found=1}
        END {exit found ? 0 : 1}
    '; then
        echo \"ALIAS: \$DOMAIN nằm trong cPanel parked_domains\"
        exit 1
    fi

    if printf '%s\n' \"\$domain_info\" | awk -v d=\"\$DOMAIN\" '
        /^[[:space:]]*(main_domain|addon_domains|sub_domains):/ {section=\"ok\"; next}
        /^[[:space:]]*[a-z_]+:/ {section=\"\"}
        section == \"ok\" && (\$0 ~ \"^[[:space:]]*\" d \"\$\" || \$0 ~ \"- \" d \"\$\") {found=1}
        END {exit found ? 0 : 1}
    '; then
        echo \"OK: \$DOMAIN không nằm trong parked_domains của cPanel\"
        exit 0
    fi
fi

if grep -Eq \"^(DNS|XDNS|ADDON)[0-9]*=\$DOMAIN$\" \"/var/cpanel/users/\$OWNER\" 2>/dev/null; then
    echo \"OK: \$DOMAIN có trong danh sách domain chính/addon của cPanel user\"
    exit 0
fi

if grep -Eq \"^(PARKED|XPARKED)[0-9]*=\$DOMAIN$\" \"/var/cpanel/users/\$OWNER\" 2>/dev/null; then
    echo \"ALIAS: \$DOMAIN nằm trong danh sách parked domain của cPanel user\"
    exit 1
fi

echo \"UNKNOWN: Không xác định được \$DOMAIN có phải parked/alias trên cPanel hay không\"
exit 2
"
}

find_ssl_folder() {
    find "$HOME/Desktop" \
        -type f \
        -name "key.txt" \
        -path "*$domain*" \
        2>/dev/null | while read -r file; do

        dir=$(dirname "$file")

        if [[ -f "$dir/cert.txt" && -f "$dir/bundle.txt" ]]; then
            echo "$dir"
            return 0
        fi
    done

    return 1
}

cleanup_remote_tmp() {
    local server_ip="$1"
    local pass="$2"
    local tmp="$3"

    if [[ -n "$server_ip" && -n "$pass" && -n "$tmp" ]]; then
        log "Xóa thư mục tạm trên server: $tmp"
        ssh_root "$server_ip" "$pass" "rm -rf '$tmp'" >>"$LOG_FILE" 2>&1
    fi
}

install_cpanel_ssl() {
    local server_ip="$1"
    local pass="$2"
    local domain="$3"
    local tmp="$4"

    ssh_root "$server_ip" "$pass" "
whmapi1 installssl \
domain='$domain' \
crt=@'$tmp/cert.txt' \
key=@'$tmp/key.txt' \
cabundle=@'$tmp/bundle.txt'
" 2>&1
}

install_directadmin_ssl() {
    local server_ip="$1"
    local pass="$2"
    local owner="$3"
    local domain="$4"
    local tmp="$5"

    SSHPASS="$pass" timeout 180 sshpass -e ssh \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=10 \
        -o ServerAliveCountMax=3 \
        root@"$server_ip" \
        "OWNER='$owner' DOMAIN='$domain' TMP='$tmp' bash -s" <<'REMOTE_SCRIPT'
set -e

DOMAIN_DIR="/usr/local/directadmin/data/users/$OWNER/domains"
DOMAIN_CONF="$DOMAIN_DIR/$DOMAIN.conf"

[ -d "$DOMAIN_DIR" ] || {
    echo "Không tồn tại DOMAIN_DIR: $DOMAIN_DIR"
    exit 1
}

[ -f "$DOMAIN_CONF" ] || {
    echo "Không tồn tại DOMAIN_CONF: $DOMAIN_CONF"
    exit 1
}

# CMD_API_SSL cần private key và leaf certificate trong cùng một trường.
API_PEM="$TMP/directadmin-api.pem"
{
    cat "$TMP/key.txt"
    printf '\n'
    cat "$TMP/cert.txt"
    printf '\n'
} > "$API_PEM"
chmod 600 "$API_PEM"

command -v curl >/dev/null 2>&1 || {
    echo "ERROR: Server thiếu curl để gọi DirectAdmin SSL API."
    exit 1
}

api_url=$(/usr/local/directadmin/directadmin api-url --user="$OWNER" 2>/dev/null)
[ -n "$api_url" ] || {
    echo "ERROR: Không tạo được DirectAdmin API URL cho user $OWNER."
    exit 1
}

cert_api_response=$(curl --silent --show-error --insecure \
    "$api_url/CMD_API_SSL" \
    --data-urlencode "domain=$DOMAIN" \
    --data-urlencode "action=save" \
    --data-urlencode "type=paste" \
    --data-urlencode "certificate@$API_PEM")

if ! printf '%s' "$cert_api_response" |
     grep -Eq '(^|&)error=0(&|$)|"error"[[:space:]]*:[[:space:]]*(0|"0")'; then
    echo "ERROR: DirectAdmin API không lưu được certificate/key."
    exit 1
fi
echo "DirectAdmin API đã lưu certificate/key cho $DOMAIN."

ca_api_response=$(curl --silent --show-error --insecure \
    "$api_url/CMD_API_SSL" \
    --data-urlencode "domain=$DOMAIN" \
    --data-urlencode "action=save" \
    --data-urlencode "type=cacert" \
    --data-urlencode "active=yes" \
    --data-urlencode "cacert@$TMP/bundle.txt")

if ! printf '%s' "$ca_api_response" |
     grep -Eq '(^|&)error=0(&|$)|"error"[[:space:]]*:[[:space:]]*(0|"0")'; then
    echo "ERROR: DirectAdmin API không lưu được CA bundle."
    exit 1
fi
echo "DirectAdmin API đã lưu CA bundle cho $DOMAIN."
rm -f "$API_PEM"

rewrite_log=$(mktemp)
if [ -x /usr/local/directadmin/directadmin ]; then
    if timeout 90 /usr/local/directadmin/directadmin taskq \
        --run="action=rewrite&value=httpd&user=$OWNER" >"$rewrite_log" 2>&1; then
        echo "Đã rewrite cấu hình webserver cho riêng user $OWNER."
    else
        echo "ERROR: DirectAdmin rewrite cấu hình webserver cho user $OWNER thất bại."
        rm -f "$rewrite_log"
        exit 1
    fi
else
    echo "ERROR: Không tìm thấy DirectAdmin CLI để rewrite cấu hình webserver."
    rm -f "$rewrite_log"
    exit 1
fi
rm -f "$rewrite_log"

USER_HTTPD_CONF="/usr/local/directadmin/data/users/$OWNER/httpd.conf"
USER_NGINX_CONF="/usr/local/directadmin/data/users/$OWNER/nginx.conf"
USER_OLS_CONF="/usr/local/directadmin/data/users/$OWNER/openlitespeed.conf"
da_webserver=$(sed -n 's/^webserver=//p' \
    /usr/local/directadmin/custombuild/options.conf 2>/dev/null | tail -n1)

configured_cert=""
case "$da_webserver" in
    apache|litespeed)
        configured_cert=$(awk -v domain="$DOMAIN" '
            /<VirtualHost[[:space:]].*:443/ {
                in_ssl_vhost=1
                block=$0 ORS
                cert=""
                next
            }
            in_ssl_vhost {
                block=block $0 ORS
                if ($1 == "SSLCertificateFile") {
                    cert=$2
                }
                if (/<\/VirtualHost>/) {
                    if (index(block, domain) > 0 && cert != "") {
                        print cert
                        exit
                    }
                    in_ssl_vhost=0
                }
            }
        ' "$USER_HTTPD_CONF" 2>/dev/null)
        ;;
    nginx|nginx_apache)
        configured_cert=$(awk -v expected="$DOMAIN_DIR/$DOMAIN.cert" '
            $1 == "ssl_certificate" {
                cert=$2
                sub(/;$/, "", cert)
                if (index(cert, expected) == 1) {
                    print cert
                    exit
                }
            }
        ' "$USER_NGINX_CONF" 2>/dev/null)
        ;;
    openlitespeed)
        configured_cert=$(awk -v expected="$DOMAIN_DIR/$DOMAIN.cert" '
            $1 == "certFile" && index($2, expected) == 1 {
                print $2
                exit
            }
        ' "$USER_OLS_CONF" 2>/dev/null)
        ;;
    *)
        echo "ERROR: Giá trị webserver DirectAdmin không được hỗ trợ: ${da_webserver:-không xác định}"
        exit 1
        ;;
esac

case "$configured_cert" in
    "$DOMAIN_DIR/$DOMAIN.cert"|"$DOMAIN_DIR/$DOMAIN.cert.combined"|"$DOMAIN_DIR/$DOMAIN.combined")
        echo "VirtualHost SSL đã trỏ đúng certificate của $DOMAIN."
        ;;
    *)
        echo "ERROR: VirtualHost SSL của $DOMAIN vẫn trỏ sai certificate: ${configured_cert:-không xác định}"
        exit 1
        ;;
esac

is_service_active() {
    service_name=$1

    if command -v systemctl >/dev/null 2>&1 &&
       systemctl is-active --quiet "$service_name" 2>/dev/null; then
        return 0
    fi

    if command -v pgrep >/dev/null 2>&1 &&
       pgrep -x "$service_name" >/dev/null 2>&1; then
        return 0
    fi

    return 1
}

reload_done=0
webserver_found=0
syntax_log=$(mktemp)

if command -v nginx >/dev/null 2>&1 &&
   { [ "$da_webserver" = "nginx" ] || [ "$da_webserver" = "nginx_apache" ] ||
     { [ -z "$da_webserver" ] && is_service_active nginx; }; }; then
    webserver_found=1
    if nginx -t >"$syntax_log" 2>&1; then
        echo "Syntax nginx OK."
        if systemctl reload nginx >/dev/null 2>&1 || \
           service nginx reload >/dev/null 2>&1 || \
           nginx -s reload >/dev/null 2>&1; then
            echo "Đã reload nginx graceful thành công."
            reload_done=1
        else
            echo "WARNING: Reload nginx thất bại."
        fi
    else
        echo "WARNING: nginx -t lỗi, bỏ qua reload nginx."
    fi
fi

if { [ "$da_webserver" = "apache" ] || [ "$da_webserver" = "nginx_apache" ] ||
     { [ -z "$da_webserver" ] &&
       { is_service_active httpd || is_service_active apache2; }; }; }; then
    webserver_found=1
    if command -v apachectl >/dev/null 2>&1; then
        if apachectl configtest >"$syntax_log" 2>&1; then
            echo "Syntax Apache OK."
            if systemctl reload httpd >/dev/null 2>&1 || \
               systemctl reload apache2 >/dev/null 2>&1 || \
               service httpd reload >/dev/null 2>&1 || \
               service apache2 reload >/dev/null 2>&1 || \
               apachectl graceful >/dev/null 2>&1; then
                echo "Đã reload Apache graceful thành công."
                reload_done=1
            else
                echo "WARNING: Reload Apache thất bại."
            fi
        else
            # Không đưa toàn bộ warning/error của các domain khác vào log cài SSL.
            echo "WARNING: apachectl configtest lỗi, bỏ qua reload Apache."
        fi
    elif command -v httpd >/dev/null 2>&1; then
        if httpd -t >"$syntax_log" 2>&1; then
            echo "Syntax httpd OK."
            if systemctl reload httpd >/dev/null 2>&1 || \
               service httpd reload >/dev/null 2>&1 || \
               httpd -k graceful >/dev/null 2>&1; then
                echo "Đã reload httpd graceful thành công."
                reload_done=1
            else
                echo "WARNING: Reload httpd thất bại."
            fi
        else
            echo "WARNING: httpd -t lỗi, bỏ qua reload httpd."
        fi
    else
        echo "WARNING: Apache đang chạy nhưng không tìm thấy lệnh configtest; bỏ qua reload Apache."
    fi
fi

if [ "$da_webserver" = "openlitespeed" ]; then
    webserver_found=1
    if [ -x /usr/local/lsws/bin/openlitespeed ] &&
       /usr/local/lsws/bin/openlitespeed -t >"$syntax_log" 2>&1; then
        echo "Syntax OpenLiteSpeed OK."
        if [ -x /usr/local/lsws/bin/lswsctrl ] &&
           /usr/local/lsws/bin/lswsctrl reload >/dev/null 2>&1; then
            echo "Đã reload OpenLiteSpeed graceful thành công."
            reload_done=1
        else
            echo "WARNING: Reload OpenLiteSpeed thất bại."
        fi
    else
        echo "WARNING: openlitespeed -t lỗi hoặc không tồn tại, bỏ qua reload OpenLiteSpeed."
    fi
fi

if [ "$da_webserver" = "litespeed" ]; then
    webserver_found=1

    # lshttpd -t chỉ test license, không phải syntax. LiteSpeed Enterprise
    # không cung cấp configtest CLI riêng; kiểm tra các phần SSL của vhost
    # trước graceful reload và xác minh certificate live ở bước kế tiếp.
    configured_key=$(awk -v domain="$DOMAIN" '
        /<VirtualHost[[:space:]].*:443/ {
            in_ssl_vhost=1
            block=$0 ORS
            key=""
            next
        }
        in_ssl_vhost {
            block=block $0 ORS
            if ($1 == "SSLCertificateKeyFile") {
                key=$2
            }
            if (/<\/VirtualHost>/) {
                if (index(block, domain) > 0 && key != "") {
                    print key
                    exit
                }
                in_ssl_vhost=0
            }
        }
    ' "$USER_HTTPD_CONF" 2>/dev/null)

    cert_public_key=$(openssl x509 -in "$configured_cert" -pubkey -noout 2>/dev/null |
        openssl pkey -pubin -outform DER 2>/dev/null |
        openssl sha256 2>/dev/null)
    private_public_key=$(openssl pkey -in "$configured_key" -pubout -outform DER 2>/dev/null |
        openssl sha256 2>/dev/null)

    if [ -n "$cert_public_key" ] &&
       [ "$cert_public_key" = "$private_public_key" ]; then
        echo "Cấu hình SSL LiteSpeed hợp lệ: certificate và private key khớp."
        if [ -x /usr/local/lsws/bin/lswsctrl ]; then
            if /usr/local/lsws/bin/lswsctrl reload >/dev/null 2>&1; then
                echo "Đã reload LiteSpeed graceful thành công."
                reload_done=1
            else
                echo "WARNING: Reload LiteSpeed thất bại."
            fi
        else
            echo "WARNING: Không tìm thấy lswsctrl, bỏ qua reload LiteSpeed."
        fi
    else
        echo "WARNING: Certificate/private key trong vhost LiteSpeed không hợp lệ, bỏ qua reload."
    fi
fi

rm -f "$syntax_log"

if [ "$webserver_found" -eq 0 ]; then
    echo "ERROR: Không phát hiện webserver phù hợp để kiểm tra và reload."
    exit 1
elif [ "$reload_done" -eq 0 ]; then
    echo "ERROR: Không webserver nào được reload thành công."
    exit 1
fi

installed_fingerprint=$(openssl x509 -in "$DOMAIN_DIR/$DOMAIN.cert" \
    -noout -fingerprint -sha256 2>/dev/null | sed 's/^[^=]*=//')
[ -n "$installed_fingerprint" ] || {
    echo "ERROR: Không đọc được fingerprint certificate vừa cài."
    exit 1
}
domain_ip=$(sed -n 's/^ip=//p' "$DOMAIN_CONF" 2>/dev/null | tail -n1)
[ -n "$domain_ip" ] || {
    echo "ERROR: Không xác định được IP của $DOMAIN trong DirectAdmin."
    exit 1
}
case "$domain_ip" in
    *:*) live_endpoint="[$domain_ip]:443" ;;
    *)   live_endpoint="$domain_ip:443" ;;
esac

live_fingerprint=""
attempt=1
# Đây chỉ là hậu kiểm. Graceful reload của LiteSpeed có thể trả về trước khi
# worker mới phục vụ certificate, nên thử lại trong thời gian ngắn nhưng không
# coi việc certificate live chưa cập nhật là lỗi cài đặt.
max_attempts=5
while [ "$attempt" -le "$max_attempts" ]; do
    live_fingerprint=$(timeout 3 openssl s_client \
        -connect "$live_endpoint" \
        -servername "$DOMAIN" </dev/null 2>/dev/null |
        openssl x509 -noout -fingerprint -sha256 2>/dev/null |
        sed 's/^[^=]*=//')

    [ -n "$live_fingerprint" ] && [ "$live_fingerprint" = "$installed_fingerprint" ] && break
    if [ "$attempt" -eq 1 ]; then
        echo "Certificate live chưa cập nhật; đang chờ webserver hoàn tất graceful reload..."
    fi
    sleep 2
    attempt=$((attempt + 1))
done

if [ -z "$live_fingerprint" ] || [ "$live_fingerprint" != "$installed_fingerprint" ]; then
    echo "WARNING: Certificate live của $DOMAIN chưa khớp certificate vừa cài; bỏ qua hậu kiểm."
    echo "Fingerprint mong đợi: $installed_fingerprint"
    echo "Fingerprint live: ${live_fingerprint:-không đọc được}"
else
    echo "Certificate live của $DOMAIN đã khớp certificate vừa cài (lần kiểm tra $attempt/$max_attempts)."
fi

if [ -s "$DOMAIN_DIR/$DOMAIN.key" ] && \
   [ -s "$DOMAIN_DIR/$DOMAIN.cert" ] && \
   [ -s "$DOMAIN_DIR/$DOMAIN.cacert" ] && \
   [ -s "$DOMAIN_DIR/$DOMAIN.cert.combined" ]; then
    echo "DirectAdmin SSL installed successfully for $OWNER:$DOMAIN"
else
    echo "DirectAdmin SSL files missing or empty for $OWNER:$DOMAIN"
    exit 1
fi
REMOTE_SCRIPT
}

check_dependencies

if [ "$NO_GUI" = true ]; then
    domain="$DOMAIN"
    server_input="$SERVER_INPUT"
    input_pass="$INPUT_PASS"
    key="$KEY_FILE"
    crt="$CERT_FILE"
    cab="$BUNDLE_FILE"
    show_log_window
else
    form=$(zenity --forms \
        --title="Install SSL Auto - cPanel / DirectAdmin" \
        --text="Nhập thông tin SSL" \
        --add-entry="Domain" \
        --add-entry="Server IP/Hostname" \
        --add-password="Root Password (bỏ trống thì lấy từ pass.csv)" \
        --separator="|")
    form_status=$?
    [ "$form_status" -ne 0 ] && exit 0

    domain=$(echo "$form" | cut -d'|' -f1 | xargs)
    server_input=$(clean_target "$(echo "$form" | cut -d'|' -f2)")
    input_pass=$(echo "$form" | cut -d'|' -f3)

    show_log_window
fi

if [ "$NO_GUI" = true ]; then
    log "Bắt đầu install SSL (no-gui mode)"
else
    log "Bắt đầu install SSL"
fi
log "Domain nhập: $domain"
log "Server nhập: $server_input"

log "Kiểm tra định dạng domain..."
if ! validate_domain "$domain"; then
    error_exit "Domain không hợp lệ: $domain"
fi
log "OK: Domain hợp lệ"

if [ -z "$server_input" ]; then
    server_input="$domain"
    log "Server bỏ trống, dùng A record của domain: $domain"
fi

log "Resolve Server IP..."
server_ip=$(resolve_server_ip "$server_input")
if [ -z "$server_ip" ]; then
    error_exit "Không resolve được IP từ server: $server_input"
fi
log "OK: Server IP = $server_ip"

if [ -n "$input_pass" ]; then
    pass="$input_pass"
    log "OK: Đã lấy root password từ popup input"
else
    log "Root password bỏ trống, lấy từ pass.csv..."
    pass=$(get_root_password "$server_ip")
    pass_status=$?

    if [ $pass_status -eq 2 ]; then
        error_exit "Không tìm thấy file pass.csv: $PASS_CSV"
    fi

    if [ $pass_status -ne 0 ] || [ -z "$pass" ]; then
        error_exit "Không tìm thấy password cho IP '$server_ip' trong pass.csv"
    fi

    log "OK: Đã lấy password từ pass.csv"
fi

if [ "$NO_GUI" = true ] && [ -n "$key" ] && [ -n "$crt" ] && [ -n "$cab" ]; then
    log "Sử dụng file SSL được truyền qua tham số command line"
else
    log "Tìm bộ SSL trong Desktop..."
    base=$(find_ssl_folder)

    if [ -z "$base" ]; then
        error_exit "Không tìm thấy bộ SSL của $domain trong Desktop. Cần đủ key.txt, cert.txt, bundle.txt"
    fi
    log "OK: SSL folder = $base"

    key="$base/key.txt"
    crt="$base/cert.txt"
    cab="$base/bundle.txt"
fi

log "Kiểm tra file SSL..."
for f in "$key" "$crt" "$cab"; do
    [ -f "$f" ] || error_exit "Không tìm thấy file: $f"
    log "OK: $f"
done

log "Convert CRLF về LF..."
sed -i 's/\r$//' "$key" "$crt" "$cab" >>"$LOG_FILE" 2>&1
log "OK: Đã xử lý line ending"

log "Kiểm tra cert.txt..."
openssl x509 -in "$crt" -noout >>"$LOG_FILE" 2>&1 || error_exit "cert.txt không hợp lệ"
log "OK: cert.txt hợp lệ"

log "Kiểm tra key.txt..."
openssl rsa -in "$key" -check -noout >>"$LOG_FILE" 2>&1 || error_exit "key.txt không hợp lệ hoặc không phải RSA private key"
log "OK: key.txt hợp lệ"

log "Kiểm tra bundle.txt..."
grep -q "BEGIN CERTIFICATE" "$cab" || error_exit "bundle.txt không có BEGIN CERTIFICATE"
log "OK: bundle.txt hợp lệ"

log "Kiểm tra private key có khớp certificate..."
cert_md5=$(openssl x509 -noout -modulus -in "$crt" 2>/dev/null | openssl md5 | awk '{print $2}')
key_md5=$(openssl rsa -noout -modulus -in "$key" 2>/dev/null | openssl md5 | awk '{print $2}')

if [ "$cert_md5" != "$key_md5" ]; then
    error_exit "Private key không khớp certificate. Cert MD5: $cert_md5 | Key MD5: $key_md5"
fi
log "OK: Private key khớp certificate"

log "Kiểm tra control panel..."
control_panel=$(detect_control_panel "$server_ip" "$pass")
panel_status=$?

if [ $panel_status -eq 2 ]; then
    error_exit "Không thể kiểm tra control panel qua SSH. Xem lỗi SSH phía trên. IP: $server_ip"
fi

if [ $panel_status -ne 0 ] || [ -z "$control_panel" ]; then
    error_exit "Server không phải cPanel/WHM hoặc DirectAdmin. IP: $server_ip"
fi
log "OK: Control panel = $control_panel"

log "Kiểm tra domain owner..."
if [ "$control_panel" = "cPanel" ]; then
    owner=$(get_cpanel_domain_owner "$server_ip" "$pass" "$domain" | xargs)
else
    owner=$(get_directadmin_domain_owner "$server_ip" "$pass" "$domain" | xargs)
fi

if [ -z "$owner" ]; then
    error_exit "Không tìm thấy owner của domain $domain trên $control_panel"
fi
log "OK: Owner = $owner"

log "Kiểm tra domain alias/parked/pointer..."
if [ "$control_panel" = "cPanel" ]; then
    domain_type_result=$(check_cpanel_domain_alias "$server_ip" "$pass" "$owner" "$domain" 2>&1)
    domain_type_status=$?
else
    domain_type_result=$(check_directadmin_domain_alias "$server_ip" "$pass" "$owner" "$domain" 2>&1)
    domain_type_status=$?
fi

echo "$domain_type_result" >>"$LOG_FILE"

if [ $domain_type_status -eq 1 ]; then
    error_exit "Domain $domain là alias/parked/pointer trên $control_panel. Dừng để tránh ghi SSL sai vhost."
fi

if [ $domain_type_status -ne 0 ]; then
    error_exit "Không xác định được loại domain $domain trên $control_panel. Dừng để an toàn."
fi
log "OK: Domain không phải alias/parked/pointer"

tmp="/root/tmp/ssl-$domain"

log "Tạo thư mục tạm trên server: $tmp"
if ! ssh_root "$server_ip" "$pass" "rm -rf '$tmp' && mkdir -p '$tmp'" >>"$LOG_FILE" 2>&1; then
    error_exit "Không tạo được thư mục tạm trên server: $tmp"
fi
log "OK: Đã tạo thư mục tạm"

log "Upload key.txt..."
SSHPASS="$pass" sshpass -e scp -o StrictHostKeyChecking=no "$key" root@"$server_ip":"$tmp/key.txt" >>"$LOG_FILE" 2>&1
scp_key_status=$?
[ $scp_key_status -eq 0 ] && log "OK: Upload key.txt"

log "Upload cert.txt..."
SSHPASS="$pass" sshpass -e scp -o StrictHostKeyChecking=no "$crt" root@"$server_ip":"$tmp/cert.txt" >>"$LOG_FILE" 2>&1
scp_crt_status=$?
[ $scp_crt_status -eq 0 ] && log "OK: Upload cert.txt"

log "Upload bundle.txt..."
SSHPASS="$pass" sshpass -e scp -o StrictHostKeyChecking=no "$cab" root@"$server_ip":"$tmp/bundle.txt" >>"$LOG_FILE" 2>&1
scp_cab_status=$?
[ $scp_cab_status -eq 0 ] && log "OK: Upload bundle.txt"

if [ $scp_key_status -ne 0 ] || [ $scp_crt_status -ne 0 ] || [ $scp_cab_status -ne 0 ]; then
    cleanup_remote_tmp "$server_ip" "$pass" "$tmp"
    error_exit "Upload file SSL lên server thất bại"
fi

if [ "$control_panel" = "cPanel" ]; then
    log "Cài SSL bằng WHM/cPanel API..."
    result=$(install_cpanel_ssl "$server_ip" "$pass" "$domain" "$tmp")
    ssh_status=$?

    log "Kết quả WHM/cPanel:"
    echo "$result" >>"$LOG_FILE"

    if echo "$result" | grep -qE "result: 1|status: 1"; then
        install_status=0
    else
        install_status=1
    fi
else
    log "Cài SSL bằng DirectAdmin filesystem + task.queue..."
    result=$(install_directadmin_ssl "$server_ip" "$pass" "$owner" "$domain" "$tmp" 2>&1)
    ssh_status=$?

    log "Kết quả DirectAdmin:"
    echo "$result" >>"$LOG_FILE"

    install_status=$ssh_status
fi

cleanup_remote_tmp "$server_ip" "$pass" "$tmp"

if [ $ssh_status -ne 0 ] || [ $install_status -ne 0 ]; then
    log "FAILED: Install SSL thất bại"
    wait_log_close
    exit 1
fi

log "SUCCESS: Install SSL thành công"
wait_log_close
exit 0
