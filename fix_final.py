import os
import re

CSS_PATH = 'static/css/style.css'
with open(CSS_PATH, 'r', encoding='utf-8') as f:
    css_content = f.read()

# Remove anything after the very first marker
marker1 = '/* --- NEW UNIFIED B&W UI STYLE (APPENDED) --- */'
marker2 = '/* --- MORE UI FIXES FOR COMPACTNESS & COLORLESS --- */'

if marker1 in css_content:
    css_content = css_content[:css_content.find(marker1)]
elif marker2 in css_content:
    css_content = css_content[:css_content.find(marker2)]

new_css = """
/* --- NEW UNIFIED B&W UI STYLE (APPENDED) --- */

/* 1. Sleek, colorless, transparent buttons */
.btn, .btn-primary, .btn-secondary, .btn-success, .btn-danger, .btn-info, .btn-warning {
    background: transparent !important;
    color: #475569 !important; /* slate-600 */
    border: 1px solid #cbd5e1 !important; /* slate-300 */
    box-shadow: 0 1px 2px rgba(15,23,42,0.02) !important;
    transition: all 0.2s ease !important;
    padding: 8px 16px !important;
    font-size: 0.9rem !important;
    font-weight: 500 !important;
    border-radius: 8px !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
    gap: 6px !important;
}
.btn:hover, .btn-primary:hover, .btn-secondary:hover, .btn-success:hover, .btn-danger:hover, .btn-info:hover, .btn-warning:hover {
    background: #f1f5f9 !important; /* slate-100 */
    color: #0f172a !important; /* slate-900 */
    border-color: #94a3b8 !important; /* slate-400 */
}
.btn:active, .btn-primary:active, .btn-secondary:active, .btn-success:active, .btn-danger:active, .btn-info:active, .btn-warning:active {
    background: #e2e8f0 !important; /* slate-200 */
    transform: translateY(0) !important;
}

/* 2. Record types checkboxes (A, AAAA, CNAME) */
.record-types label {
    min-height: unset !important;
    padding: 6px 12px !important;
    border-radius: 6px !important;
    background: transparent !important;
    border: 1px solid #cbd5e1 !important;
    box-shadow: none !important;
    color: #475569 !important;
    font-size: 0.85rem !important;
    font-weight: 500 !important;
    gap: 6px !important;
    transition: all 0.2s ease !important;
}
.record-types label:hover {
    background: #f1f5f9 !important;
    border-color: #94a3b8 !important;
    color: #0f172a !important;
}
.record-types label input[type="checkbox"] {
    accent-color: #64748b !important;
    width: 14px !important;
    height: 14px !important;
    margin: 0 !important;
}

/* 3. Detail/Basic toggle buttons */
.dns-view-btn, .history-source-btn, .challenge-type-btn, .copy-btn-small {
    background: transparent !important;
    color: #64748b !important;
    border: 1px solid transparent !important;
    border-radius: 6px !important;
    padding: 6px 12px !important;
    box-shadow: none !important;
}
.dns-view-btn:hover, .history-source-btn:hover, .challenge-type-btn:hover, .copy-btn-small:hover {
    background: #f1f5f9 !important;
    color: #0f172a !important;
    border-color: #cbd5e1 !important;
}
.dns-view-btn.active, .history-source-btn.active, .challenge-type-btn.selected {
    background: #ffffff !important;
    color: #0f172a !important;
    border: 1px solid #cbd5e1 !important;
    box-shadow: 0 2px 4px rgba(15,23,42,0.04) !important;
}

.dns-view-switch {
    background: rgba(241, 245, 249, 0.5) !important;
    border: 1px solid #e2e8f0 !important;
    border-radius: 8px !important;
    padding: 4px !important;
}

/* 4. Icon-only buttons perfectly square */
.dns-actions .btn, .search-row .btn {
    padding: 0 !important;
    width: 44px !important; 
    height: 44px !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
    font-size: 1.1rem !important;
}

/* 5. Specific overrides for any green/red icon boxes */
.dnssec-status.enabled .dnssec-icon, 
.dnssec-state.enabled .dnssec-state-icon,
.dnssec-status.disabled .dnssec-icon, 
.dnssec-state.disabled .dnssec-state-icon {
    background: transparent !important;
    color: #475569 !important;
    border: 1px solid #cbd5e1 !important;
}

/* Remove gradient colors entirely */
:root {
    --ui-accent: #64748b !important;
    --ui-accent-strong: #475569 !important;
}
"""

with open(CSS_PATH, 'w', encoding='utf-8') as f:
    f.write(css_content.rstrip() + '\n' + new_css)
print('Reverted text-shadow hack in CSS.')

# Now, parse all HTML files in templates/tabs and replace emojis in buttons with Lucide icons
TABS_DIR = 'templates/tabs'
emoji_map = {
    '🔍': '<span class="icon" data-lucide="search"></span>',
    '🗑️': '<span class="icon" data-lucide="trash-2"></span>',
    '🛡️': '<span class="icon" data-lucide="shield"></span>',
    '📋': '<span class="icon" data-lucide="clipboard"></span>',
    '⬇️': '<span class="icon" data-lucide="download"></span>',
    '📄': '<span class="icon" data-lucide="file"></span>',
    '📚': '<span class="icon" data-lucide="files"></span>',
    '📝': '<span class="icon" data-lucide="edit-3"></span>',
    '📂': '<span class="icon" data-lucide="folder"></span>',
    '📁': '<span class="icon" data-lucide="folder-plus"></span>',
    '🔑': '<span class="icon" data-lucide="key"></span>',
    '🎁': '<span class="icon" data-lucide="gift"></span>',
    '⚙️': '<span class="icon" data-lucide="settings"></span>',
    '🗂️': '<span class="icon" data-lucide="archive"></span>',
    '🏁': '<span class="icon" data-lucide="flag"></span>',
    '🎉': '<span class="icon" data-lucide="award"></span>',
    '🖥️': '<span class="icon" data-lucide="monitor"></span>',
    '🔒': '<span class="icon" data-lucide="lock"></span>',
    '🔐': '<span class="icon" data-lucide="unlock"></span>',
    '🔗': '<span class="icon" data-lucide="link"></span>',
    '📜': '<span class="icon" data-lucide="file-text"></span>',
    '🌐': '<span class="icon" data-lucide="globe"></span>',
    '➕': '<span class="icon" data-lucide="plus"></span>',
    '🚀': '<span class="icon" data-lucide="rocket"></span>'
}

def replace_emojis(match):
    text = match.group(0)
    for emoji, icon in emoji_map.items():
        text = text.replace(emoji, icon)
    return text

files = os.listdir(TABS_DIR)
for file in files:
    if not file.endswith('.html'): continue
    filepath = os.path.join(TABS_DIR, file)
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # We replace emojis everywhere (headers, buttons, etc.) to ensure complete consistency
    for emoji, icon in emoji_map.items():
        content = content.replace(emoji, icon)
        
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

print('Replaced emojis with Lucide icons in all tabs.')
