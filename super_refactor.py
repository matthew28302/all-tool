import re

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. CSS Injection (Dashboard + Pastel)
css_injection = '''
        /* --- DASHBOARD LAYOUT & PASTEL THEME --- */
        :root {
            --primary: #818cf8;
            --primary-hover: #6366f1;
            --primary-light: #e0e7ff;
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --text-main: #334155;
            --text-muted: #94a3b8;
            --border-color: #e2e8f0;
            
            --success-bg: #ecfdf5;
            --success-text: #10b981;
            --success-border: #a7f3d0;
            
            --danger-bg: #fff1f2;
            --danger-text: #f43f5e;
            --danger-border: #fecdd3;
            
            --warning-bg: #fffbeb;
            --warning-text: #f59e0b;
            --warning-border: #fde68a;

            --shadow-sm: 0 1px 2px rgba(0,0,0,0.02);
            --shadow-md: 0 4px 12px rgba(0,0,0,0.03), 0 2px 4px rgba(0,0,0,0.02);
            --shadow-lg: 0 12px 24px rgba(0,0,0,0.04);
            --radius-md: 10px;
            --radius-lg: 16px;
            --radius-pill: 999px;
            --font-sans: 'Be Vietnam Pro', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        body { 
            margin: 0; 
            overflow: hidden; 
            background-color: var(--bg-body);
            font-family: var(--font-sans);
            color: var(--text-main);
            line-height: 1.6;
        }
        
        .dashboard-layout {
            display: flex;
            height: 100vh;
            width: 100vw;
            overflow: hidden;
        }

        .sidebar {
            width: 280px;
            background: var(--bg-card);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            flex-shrink: 0;
            z-index: 100;
            transition: transform 0.3s ease;
        }

        .sidebar-header {
            padding: 24px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .sidebar-header h2 { font-size: 1.25rem; font-weight: 800; color: var(--primary); margin: 0; }
        .sidebar-close { display: none; background: none; border: none; font-size: 1.5rem; color: var(--text-muted); cursor: pointer; }

        .sidebar-menu {
            padding: 20px 16px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        .sidebar-group-title {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-muted);
            font-weight: 700;
            margin-bottom: 8px;
            padding-left: 12px;
        }

        .sidebar .tab-btn {
            width: 100%;
            justify-content: flex-start;
            padding: 10px 16px;
            margin-bottom: 4px;
            background: transparent;
            border: none;
            box-shadow: none;
            color: var(--text-muted);
            border-radius: 8px;
            font-size: 0.95rem;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .sidebar .tab-btn:hover {
            background: var(--primary-light);
            color: var(--primary);
        }
        
        .sidebar .tab-btn.active {
            background: var(--primary);
            color: #ffffff;
            font-weight: 700;
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
        }

        .main-content {
            flex-grow: 1;
            height: 100vh;
            overflow-y: auto;
            padding: 32px;
            background: var(--bg-body);
        }
        
        .tab-content {
            border: none;
            box-shadow: none;
            background: transparent;
            padding: 0;
            margin: 0;
        }
        
        .mobile-header {
            display: none;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            background: var(--bg-card);
            border-bottom: 1px solid var(--border-color);
        }
        
        .menu-toggle {
            background: none;
            border: none;
            font-size: 1.5rem;
            color: var(--text-main);
            cursor: pointer;
        }

        @media (max-width: 992px) {
            body { overflow: auto; }
            .dashboard-layout { flex-direction: column; height: auto; overflow: visible; }
            .sidebar {
                position: fixed;
                top: 0; left: 0; bottom: 0;
                transform: translateX(-100%);
                box-shadow: var(--shadow-lg);
            }
            .sidebar.open { transform: translateX(0); }
            .sidebar-close { display: block; }
            .mobile-header { display: flex; }
            .main-content { padding: 16px; height: auto; overflow: visible; }
        }

        /* --- INNER TAB PASTEL STYLES --- */
        h1, h2, h3, h4, h5, h6, .dns-panel-title, .history-bucket-title, .section-title {
            color: #475569;
            font-weight: 700;
        }

        /* Input Groups */
        .input-group {
            display: flex;
            width: 100%;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-sm);
            overflow: hidden;
            border: 1px solid var(--border-color);
        }
        .input-group input {
            border: none !important;
            border-radius: 0 !important;
            box-shadow: none !important;
            flex-grow: 1;
            padding: 14px 20px;
            background: var(--bg-card);
            color: var(--text-main);
        }
        .input-group input:focus {
            background: #ffffff;
            box-shadow: inset 0 0 0 2px var(--primary-light) !important;
            outline: none;
        }
        .input-group .btn {
            border-radius: 0 !important;
            border: none !important;
            box-shadow: none !important;
            margin: 0;
            padding: 14px 24px;
        }

        /* Pill Toggles for Record Types */
        .record-types {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 12px;
        }
        .record-types label {
            padding: 8px 16px;
            background: var(--bg-card);
            border-radius: var(--radius-pill);
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: var(--shadow-sm);
            display: inline-flex;
        }
        .record-types label input[type="checkbox"] { display: none; }
        .record-types label:has(input:checked) {
            background: var(--primary-light);
            color: var(--primary-hover);
            border-color: var(--primary-light);
            box-shadow: none;
        }

        /* Buttons */
        .btn-primary {
            background: var(--primary);
            color: #ffffff;
            font-weight: 600;
            border-radius: var(--radius-md);
            padding: 12px 20px;
            border: none;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-primary:hover { background: var(--primary-hover); }
        .btn-secondary {
            background: #f1f5f9;
            color: #64748b;
            font-weight: 600;
            border-radius: var(--radius-md);
            padding: 12px 20px;
            border: none;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-secondary:hover { background: #e2e8f0; color: #475569; }

        /* Cards & Tables */
        .summary-card, .history-summary-card, .dns-stat-row, .dns-card, .installssl-panel {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-sm);
        }
        .record-col-header, .installssl-log-header {
            background: #f8fafc;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
        }
        .server-row { border-bottom: 1px dashed var(--border-color); }
        .server-row:hover { background: #f1f5f9; }

        /* Badges */
        .rate.full, .dnssec-status.enabled, .record-value, .history-summary-value.success {
            background: var(--success-bg);
            color: var(--success-text);
            border: 1px solid var(--success-border);
        }
        .rate.none, .dnssec-status.disabled, .no-record, .history-summary-value.error {
            background: var(--danger-bg);
            color: var(--danger-text);
            border: 1px solid var(--danger-border);
        }
        .rate.partial, .history-summary-value.warning {
            background: var(--warning-bg);
            color: var(--warning-text);
            border: 1px solid var(--warning-border);
        }
'''

content = content.replace('</style>', css_injection + '\n</style>')

# 2. HTML Restructure - Sidebar
old_nav_regex = re.compile(r'<div class="container">\s*<!-- Tab Navigation -->\s*<div class="tab-nav" role="tablist" aria-label="Network tool tabs">.*?</div>', re.DOTALL)
sidebar_html = '''
    <!-- Mobile Header -->
    <div class="mobile-header">
        <h2>Network Tools</h2>
        <button class="menu-toggle" onclick="document.querySelector('.sidebar').classList.toggle('open')">☰</button>
    </div>

    <div class="dashboard-layout">
        <aside class="sidebar">
            <div class="sidebar-header">
                <h2>Network Tools</h2>
                <button class="sidebar-close" onclick="document.querySelector('.sidebar').classList.remove('open')">✕</button>
            </div>
            
            <div class="sidebar-menu">
                <div class="sidebar-group">
                    <div class="sidebar-group-title">DNS Tools</div>
                    <button class="tab-btn active" data-tab="dns" id="tabbtn-dns" onclick="switchTab('dns')"><span class="icon">🔍</span> DNS</button>
                    <button class="tab-btn" data-tab="bulkdns" id="tabbtn-bulkdns" onclick="switchTab('bulkdns')"><span class="icon">🗂️</span> Bulk DNS</button>
                    <button class="tab-btn" data-tab="dnshistory" id="tabbtn-dnshistory" onclick="switchTab('dnshistory')"><span class="icon">🕰️</span> DNS History</button>
                </div>
                <div class="sidebar-group">
                    <div class="sidebar-group-title">SSL Tools</div>
                    <button class="tab-btn" data-tab="ssl" id="tabbtn-ssl" onclick="switchTab('ssl')"><span class="icon">🔒</span> SSL Bundle</button>
                    <button class="tab-btn" data-tab="installssl" id="tabbtn-installssl" onclick="switchTab('installssl')"><span class="icon">⬆️</span> Install SSL</button>
                    <button class="tab-btn" data-tab="ssldecoder" id="tabbtn-ssldecoder" onclick="switchTab('ssldecoder')"><span class="icon">🔐</span> SSL Decoder</button>
                    <button class="tab-btn" data-tab="sslcheck" id="tabbtn-sslcheck" onclick="switchTab('sslcheck')"><span class="icon">🛡️</span> SSL Check</button>
                    <button class="tab-btn" data-tab="freessl" id="tabbtn-freessl" onclick="switchTab('freessl')"><span class="icon">🎁</span> SSL Miễn Phí</button>
                </div>
                <div class="sidebar-group">
                    <div class="sidebar-group-title">Utilities</div>
                    <button class="tab-btn" data-tab="hostcheck" id="tabbtn-hostcheck" onclick="switchTab('hostcheck')"><span class="icon">🖥️</span> Host Check</button>
                </div>
                <div class="sidebar-group">
                    <div class="sidebar-group-title">AI Assistant</div>
                    <button class="tab-btn" data-tab="ai" id="tabbtn-ai" onclick="switchTab('ai')"><span class="icon">🤖</span> AI Chat</button>
                </div>
            </div>
        </aside>

        <main class="main-content">
'''
content = old_nav_regex.sub(sidebar_html, content)
content = re.sub(r'</div>\s*(<!-- JS Scripts -->|<script)', r'</main></div>\n\1', content)

# 3. DNS Check UI - Input Group
dns_search_pattern = re.compile(
    r'<div class="dns-search-row">.*?<input type="text" class="dns-input" id="domainInput".*?>.*?<div class="dns-actions">.*?<button class="btn btn-primary" onclick="checkDNS\(\)">🔍 Kiểm tra</button>.*?</div>\s*</div>',
    re.DOTALL
)

dns_search_replacer = '''<div class="dns-search-row" style="display:flex; flex-direction:column; gap:16px;">
                            <div style="display:flex; gap:12px; width:100%; align-items:center;">
                                <div class="input-group">
                                    <input type="text" class="dns-input" id="domainInput"
                                           placeholder="Nhập tên miền (vd: google.com)"
                                           onkeypress="if(event.key==='Enter')checkDNS()">
                                    <button class="btn btn-primary" onclick="checkDNS()">🔍 Kiểm tra</button>
                                </div>
                                <button class="btn btn-secondary" onclick="clearCache()" style="padding: 14px 20px;">🗑️ Clear</button>
                            </div>
                            <div class="dns-view-switch" role="group" aria-label="DNS mode">
                                <button type="button" id="dnsModeDetailBtnInline" class="dns-view-btn active" onclick="setDnsMode('detail')">Detail Mode</button>
                                <button type="button" id="dnsModeBasicBtnInline" class="dns-view-btn" onclick="setDnsMode('basic')">Basic Mode</button>
                            </div>
                        </div>'''
content = dns_search_pattern.sub(dns_search_replacer, content)

# 4. Bulk DNS UI - Textarea and buttons
bulk_dns_pattern = re.compile(
    r'<textarea id="bulkDomainInput".*?</textarea>.*?<div class="dns-actions">.*?</div>',
    re.DOTALL
)
bulk_dns_replacer = '''<textarea id="bulkDomainInput" placeholder="Nhập danh sách domain (mỗi domain 1 dòng)..." style="width:100%; min-height:120px; padding:16px; border:1px solid var(--border-color); border-radius:var(--radius-md); background:var(--bg-card); outline:none; resize:vertical; font-family:var(--font-sans); margin-bottom:12px;"></textarea>
                        <div class="dns-actions" style="display:flex; gap:12px; justify-content:flex-end;">
                            <button class="btn btn-secondary" onclick="document.getElementById('bulkDomainInput').value=''">Xóa trắng</button>
                            <button class="btn btn-primary" onclick="checkBulkDNS()">🔍 Kiểm tra Bulk</button>
                        </div>'''
content = bulk_dns_pattern.sub(bulk_dns_replacer, content)

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'w', encoding='utf-8') as f:
    f.write(content)
print('Super Refactor completed safely.')
