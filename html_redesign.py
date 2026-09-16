import re

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. New Sidebar HTML
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

# Replace the closing </div> of .container with closing for .main-content and .dashboard-layout
content = re.sub(r'</div>\s*(<!-- JS Scripts -->|<script)', r'</main></div>\n\1', content)

# 2. Add Sidebar CSS
css_injection = '''
        /* --- DASHBOARD LAYOUT OVERRIDES --- */
        body { margin: 0; overflow: hidden; }
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

        /* Override Tab Buttons for Sidebar */
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
        }
        
        .sidebar .tab-btn:hover {
            background: var(--primary-light);
            color: var(--primary);
            transform: none;
            box-shadow: none;
        }
        
        .sidebar .tab-btn.active {
            background: var(--primary);
            color: #ffffff;
            font-weight: 700;
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.2);
        }

        .main-content {
            flex-grow: 1;
            height: 100vh;
            overflow-y: auto;
            padding: 32px;
            background: var(--bg-body);
        }
        
        /* Modern Tabs to act like Pages */
        .tab-content {
            border: none;
            box-shadow: none;
            background: transparent;
            padding: 0;
            margin: 0;
            backdrop-filter: none;
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
'''

content = content.replace('/* --- MODERN REDESIGN OVERRIDES --- */', css_injection + '\n        /* --- MODERN REDESIGN OVERRIDES --- */')

# Make sure AI chat height behaves in the new layout
content = content.replace('height: calc(100vh - 120px);', 'height: calc(100vh - 64px);')

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print('Sidebar layout applied successfully.')
