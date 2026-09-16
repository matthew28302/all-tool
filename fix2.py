import re

with open('static/css/style.css', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove anything after the very first marker
marker1 = '/* --- NEW UNIFIED B&W UI STYLE (APPENDED) --- */'
marker2 = '/* --- MORE UI FIXES FOR COMPACTNESS & COLORLESS --- */'

if marker1 in content:
    content = content[:content.find(marker1)]
elif marker2 in content:
    content = content[:content.find(marker2)]

new_css = """
/* --- NEW UNIFIED B&W UI STYLE (APPENDED) --- */

/* Base style for ALL buttons to be fully transparent and colorless */
.btn,
.btn-primary, .btn-secondary, .btn-success, .btn-danger, .btn-info, .btn-warning, .btn-green, .btn-orange,
button.btn-primary, button.btn-secondary, button.btn-success, button.btn-danger, button.btn-info, button.btn-warning, button.btn-green, button.btn-orange {
    background: transparent !important;
    color: transparent !important; /* hide default color to let text-shadow color the emojis */
    text-shadow: 0 0 0 #64748b !important; /* forces text AND emojis to be slate-500 */
    border: 1px solid #cbd5e1 !important; /* slate-300 */
    box-shadow: none !important;
    transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
    padding: 8px 14px !important;
    font-size: 0.9rem !important;
    font-weight: 500 !important;
    border-radius: 8px !important;
    gap: 6px !important;
}

/* Hover state for buttons */
.btn:hover,
.btn-primary:hover, .btn-secondary:hover, .btn-success:hover, .btn-danger:hover, .btn-info:hover, .btn-warning:hover, .btn-green:hover, .btn-orange:hover,
button.btn-primary:hover, button.btn-secondary:hover, button.btn-success:hover, button.btn-danger:hover, button.btn-info:hover, button.btn-warning:hover, button.btn-green:hover, button.btn-orange:hover {
    background: rgba(255, 255, 255, 0.9) !important;
    text-shadow: 0 0 0 #0f172a !important; /* slate-900 */
    border-color: #94a3b8 !important; /* slate-400 */
    box-shadow: 0 4px 12px rgba(15, 23, 42, 0.03) !important;
    transform: translateY(-1px) !important;
}

.btn:active,
.btn-primary:active, .btn-secondary:active, .btn-success:active, .btn-danger:active, .btn-info:active, .btn-warning:active, .btn-green:active, .btn-orange:active {
    transform: translateY(0) !important;
    box-shadow: 0 1px 2px rgba(15, 23, 42, 0.02) !important;
    background: rgba(241, 245, 249, 0.8) !important; /* slate-100 */
}

/* Icons (SVGs/Img) - Black and White Style */
i, .icon, svg, img, .dnssec-icon, .ssl-choice-icon {
    filter: grayscale(100%) !important;
}

/* Record types checkboxes (A, AAAA, CNAME) */
.record-types label {
    min-height: unset !important;
    padding: 6px 12px !important;
    border-radius: 6px !important;
    background: transparent !important;
    border: 1px solid #cbd5e1 !important;
    box-shadow: none !important;
    color: transparent !important;
    text-shadow: 0 0 0 #64748b !important;
    font-size: 0.85rem !important;
    font-weight: 500 !important;
    gap: 6px !important;
    transition: all 0.2s ease !important;
}
.record-types label:hover {
    background: rgba(255, 255, 255, 0.9) !important;
    border-color: #94a3b8 !important;
    text-shadow: 0 0 0 #0f172a !important;
}
.record-types label input[type="checkbox"] {
    accent-color: #64748b !important;
    width: 14px !important;
    height: 14px !important;
    margin: 0 !important;
}

/* Detail/Basic toggle buttons */
.dns-view-btn, .history-source-btn, .challenge-type-btn, .copy-btn-small {
    background: transparent !important;
    color: transparent !important;
    text-shadow: 0 0 0 #64748b !important;
    border: 1px solid transparent !important;
    border-radius: 6px !important;
    padding: 6px 12px !important;
    box-shadow: none !important;
}
.dns-view-btn:hover, .history-source-btn:hover, .challenge-type-btn:hover, .copy-btn-small:hover {
    background: rgba(255, 255, 255, 0.6) !important;
    text-shadow: 0 0 0 #0f172a !important;
    border-color: #cbd5e1 !important;
}
.dns-view-btn.active, .history-source-btn.active, .challenge-type-btn.selected {
    background: #ffffff !important;
    text-shadow: 0 0 0 #0f172a !important;
    border: 1px solid #cbd5e1 !important;
    box-shadow: 0 2px 4px rgba(15,23,42,0.04) !important;
}
.dns-view-switch {
    background: rgba(241, 245, 249, 0.5) !important;
    border: 1px solid #e2e8f0 !important;
    border-radius: 8px !important;
    padding: 4px !important;
}

/* Make icon-only buttons perfectly square */
.dns-actions .btn, .search-row .btn {
    padding: 0 !important;
    width: 44px !important; /* matching height of input */
    height: 44px !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
    font-size: 1.1rem !important;
}

/* Specific overrides for green/red icon boxes */
.dnssec-status.enabled .dnssec-icon, 
.dnssec-state.enabled .dnssec-state-icon,
.dnssec-status.disabled .dnssec-icon, 
.dnssec-state.disabled .dnssec-state-icon {
    background: transparent !important;
    color: transparent !important;
    text-shadow: 0 0 0 #64748b !important;
    border: 1px solid #cbd5e1 !important;
}

/* Remove gradient colors entirely */
:root {
    --ui-accent: #64748b !important;
    --ui-accent-strong: #475569 !important;
}
"""

with open('static/css/style.css', 'w', encoding='utf-8') as f:
    f.write(content.rstrip() + '\n' + new_css)
print('Fixed all buttons and emojis!')
