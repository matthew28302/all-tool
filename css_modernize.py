import re

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Extract the CSS block
css_match = re.search(r'(<style>)(.*?)(</style>)', content, re.DOTALL)
if not css_match:
    print('No CSS found')
    exit()

original_css = css_match.group(2)
css = original_css

# Global replaces for modernization:
# 1. More rounded corners (border-radius)
css = re.sub(r'border-radius:\s*(4|6|8|10|12)px;', r'border-radius: 12px;', css)
css = re.sub(r'border-radius:\s*(14|16|18)px;', r'border-radius: 16px;', css)

# 2. Softer borders (replace solid borders with softer colors or completely if card)
css = re.sub(r'border:\s*1px solid #(e2e8f0|cbd5e1);', r'border: 1px solid rgba(226, 232, 240, 0.8);', css)

# 3. Modern Box Shadows
css = re.sub(r'box-shadow:\s*0 1px 3px rgba\(0,0,0,0\.1\);', r'box-shadow: 0 4px 20px rgba(0,0,0,0.04), 0 1px 3px rgba(0,0,0,0.02);', css)
css = re.sub(r'box-shadow:\s*0 4px 15px rgba\(15,\s*23,\s*42,\s*0\.03\);', r'box-shadow: 0 10px 40px rgba(0,0,0,0.04), 0 2px 6px rgba(0,0,0,0.02);', css)

# 4. Inputs & Buttons Height
css = re.sub(r'padding:\s*14px 18px;', r'padding: 14px 20px;', css) # Search inputs
css = re.sub(r'padding:\s*12px 14px;', r'padding: 14px 16px;', css) # Normal inputs
css = re.sub(r'min-height:\s*60px;', r'min-height: 54px;', css) # textareas

# Let's inject a global modern CSS block at the very end of the <style>
modern_css = '''
        /* --- MODERN REDESIGN OVERRIDES --- */
        :root {
            --primary: #4F46E5;
            --primary-hover: #4338CA;
            --primary-light: #EEF2FF;
            --bg-body: #F8FAFC;
            --bg-card: #FFFFFF;
            --text-main: #0F172A;
            --text-muted: #64748B;
            --border-color: #E2E8F0;
            --shadow-sm: 0 2px 4px rgba(0,0,0,0.02);
            --shadow-md: 0 10px 25px rgba(0,0,0,0.04), 0 4px 6px rgba(0,0,0,0.02);
            --shadow-lg: 0 20px 40px rgba(0,0,0,0.06);
            --radius-md: 12px;
            --radius-lg: 16px;
            --radius-pill: 999px;
            --font-sans: 'Be Vietnam Pro', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        body {
            background-color: var(--bg-body);
            background-image: 
                radial-gradient(at 0% 0%, hsla(253,16%,7%,0.02) 0, transparent 50%), 
                radial-gradient(at 50% 0%, hsla(225,39%,30%,0.02) 0, transparent 50%), 
                radial-gradient(at 100% 0%, hsla(339,49%,30%,0.02) 0, transparent 50%);
            background-attachment: fixed;
            font-family: var(--font-sans);
            color: var(--text-main);
            line-height: 1.6;
        }

        .container {
            max-width: 1280px;
            padding: 24px;
        }

        /* Modernize Tabs */
        .tab-nav {
            background: transparent;
            box-shadow: none;
            gap: 12px;
            padding: 12px 0;
            margin-bottom: 24px;
        }
        
        .tab-btn {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-pill);
            box-shadow: var(--shadow-sm);
            padding: 12px 24px;
            color: var(--text-muted);
            font-weight: 600;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .tab-btn:hover {
            background: var(--bg-card);
            border-color: #cbd5e1;
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
            color: var(--text-main);
        }
        
        .tab-btn.active {
            background: var(--primary);
            border-color: var(--primary);
            color: #ffffff;
            box-shadow: 0 8px 16px rgba(79, 70, 229, 0.25);
            transform: translateY(-2px);
        }

        .tab-content {
            background: var(--bg-card);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-md);
            border: 1px solid rgba(255, 255, 255, 0.5);
            padding: 32px;
            backdrop-filter: blur(10px);
            animation: fadeIn 0.4s ease-out forwards;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Modernize Cards & Summaries */
        .summary-card, .history-summary-card, .dns-card, .installssl-panel {
            background: var(--bg-card);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-md);
            border: 1px solid rgba(226, 232, 240, 0.6);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .summary-card:hover, .history-summary-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-lg);
        }

        /* Inputs & Buttons */
        .search-input, .dns-input, input[type="text"], input[type="password"], textarea, select {
            border-radius: var(--radius-md);
            border: 1px solid var(--border-color);
            background: #F8FAFC;
            transition: all 0.2s ease;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.02);
        }
        
        .search-input:focus, .dns-input:focus, input[type="text"]:focus, textarea:focus, select:focus {
            background: #FFFFFF;
            border-color: var(--primary);
            box-shadow: 0 0 0 4px var(--primary-light);
            outline: none;
        }

        .btn-primary {
            background: var(--primary);
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.2);
            border-radius: var(--radius-md);
        }
        
        .btn-primary:hover {
            background: var(--primary-hover);
            transform: translateY(-1px);
            box-shadow: 0 6px 16px rgba(79, 70, 229, 0.3);
        }

        /* Tables & Lists */
        .record-header, .history-bucket-head, .history-type-head, .installssl-log-header {
            background: #F8FAFC;
            border-bottom: 1px solid var(--border-color);
        }

        .server-row:hover, .history-record-item:hover, .installssl-item:hover {
            background: #F1F5F9;
            transition: background 0.2s;
        }

        /* Badges */
        .rate.full, .dnssec-status.enabled, .record-value {
            background: #ECFDF5;
            color: #059669;
            border: 1px solid #D1FAE5;
        }

        .rate.none, .dnssec-status.disabled, .no-record {
            background: #FEF2F2;
            color: #DC2626;
            border: 1px solid #FEE2E2;
        }

        /* Scrollbars */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #CBD5E1; border-radius: 999px; }
        ::-webkit-scrollbar-thumb:hover { background: #94A3B8; }

        /* Typography fixes */
        h1, h2, h3, h4, h5, h6, .dns-panel-title, .history-bucket-title, .section-title {
            color: var(--text-main);
            letter-spacing: -0.02em;
        }
        
        /* Mobile fixes */
        @media (max-width: 640px) {
            .tab-nav { padding-bottom: 8px; }
            .tab-content { padding: 16px; }
            .container { padding: 12px; }
            
            .record-col-header {
                display: none;
            }
            .server-row {
                display: flex;
                flex-direction: column;
                align-items: flex-start;
                gap: 8px;
                padding: 16px;
            }
            .server-name { font-size: 1.05rem; }
            .server-ip { font-size: 0.9rem; }
        }
'''

new_css = css + modern_css

# Make sure to replace the exact original match!
new_content = content[:css_match.start(2)] + new_css + content[css_match.end(2):]

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'w', encoding='utf-8') as f:
    f.write(new_content)

print('Successfully applied modern CSS redesign.')
