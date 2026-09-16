import re

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Update the CSS variables for the pastel theme
pastel_css = '''
        /* --- MODERN REDESIGN OVERRIDES --- */
        :root {
            /* Pastel Soft Theme */
            --primary: #818cf8; /* Soft Indigo */
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

        /* General Inner Overrides */
        h1, h2, h3, h4, h5, h6, .dns-panel-title, .history-bucket-title, .section-title {
            color: #475569;
            font-weight: 700;
        }

        /* Pill Toggles for Checkboxes (Record Types) */
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
            align-items: center;
            justify-content: center;
        }
        .record-types label input[type="checkbox"] {
            display: none; /* Hide the actual checkbox */
        }
        .record-types label:has(input:checked) {
            background: var(--primary-light);
            color: var(--primary-hover);
            border-color: var(--primary-light);
            box-shadow: none;
        }
        .record-types label:hover:not(:has(input:checked)) {
            background: #f1f5f9;
            border-color: #cbd5e1;
        }

        /* Input Groups (Joined Input and Button) */
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
        }
        .input-group .btn {
            border-radius: 0 !important;
            border: none !important;
            box-shadow: none !important;
            margin: 0;
            padding: 14px 24px;
        }

        /* Buttons styling */
        .btn-primary {
            background: var(--primary);
            color: #ffffff;
            font-weight: 600;
        }
        .btn-primary:hover {
            background: var(--primary-hover);
        }
        
        .btn-secondary {
            background: #f1f5f9;
            color: #64748b;
        }
        .btn-secondary:hover {
            background: #e2e8f0;
            color: #475569;
        }

        /* Summary Cards / Stats (Soft backgrounds) */
        .summary-card, .history-summary-card, .dns-stat-row {
            background: var(--bg-body);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            box-shadow: none;
        }
        .summary-card:hover, .history-summary-card:hover {
            background: #ffffff;
            box-shadow: var(--shadow-md);
        }

        /* Tables and Results */
        .record-body, .installssl-panel {
            border-color: var(--border-color);
            background: #ffffff;
        }
        .record-col-header, .installssl-log-header {
            background: #f8fafc;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
        }
        .server-row {
            border-bottom: 1px dashed var(--border-color);
        }

        /* Badges & Rates */
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
        
        /* Badges inside pills */
        .dns-badge {
            background: var(--primary-light);
            color: var(--primary-hover);
            border: none;
        }

        /* Remove chunky borders */
        .dns-card, .installssl-panel {
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow-md);
        }
        .dns-search-card {
            background: #ffffff;
        }
'''

# Replace the old modern overrides with this new one
css_replacement = re.sub(r'/\* --- MODERN REDESIGN OVERRIDES ---\s*\*/.*?(?=\*/|</style>)(?:\*/)?', pastel_css, content, flags=re.DOTALL)
if '/* --- MODERN REDESIGN OVERRIDES --- */' not in content:
    # If not found for some reason, inject before </style>
    content = content.replace('</style>', pastel_css + '\n</style>')
else:
    # It might be matched by the regex. Wait, the regex looks for */ but I didn't put */ at the end of the block in the original script!
    # Let's just do a string split.
    parts = content.split('/* --- MODERN REDESIGN OVERRIDES --- */')
    if len(parts) > 1:
        # Reconstruct with only the first part, discarding everything after it (because it was the last thing injected)
        # Wait, I injected DASHBOARD LAYOUT OVERRIDES *before* MODERN REDESIGN OVERRIDES.
        # Oh, the dashboard layout was injected before it. So discarding everything after it is safe.
        content = parts[0] + pastel_css
    else:
        content = content.replace('</style>', pastel_css + '\n</style>')

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print('Pastel CSS applied successfully.')
