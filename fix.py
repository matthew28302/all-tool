css = """
/* --- MORE UI FIXES FOR COMPACTNESS & COLORLESS --- */

/* Fix the huge, deformed record-types checkboxes */
.record-types label {
    min-height: unset !important;
    padding: 6px 12px !important;
    border-radius: 6px !important;
    background: transparent !important;
    border: 1px solid #cbd5e1 !important;
    box-shadow: none !important;
    color: #64748b !important;
    font-size: 0.85rem !important;
    font-weight: 500 !important;
    gap: 6px !important;
    transition: all 0.2s ease !important;
}
.record-types label:hover {
    background: rgba(255, 255, 255, 0.9) !important;
    border-color: #94a3b8 !important;
    color: #0f172a !important;
}

/* Checkbox inside the label */
.record-types label input[type="checkbox"] {
    accent-color: #64748b !important;
    width: 14px !important;
    height: 14px !important;
    margin: 0 !important;
}

/* Fix Detail/Basic toggle buttons (and any similar toggle) */
.dns-view-btn, .history-source-btn, .challenge-type-btn, .copy-btn-small {
    background: transparent !important;
    color: #64748b !important;
    border: 1px solid transparent !important;
    border-radius: 6px !important;
    padding: 6px 12px !important;
    box-shadow: none !important;
}
.dns-view-btn:hover, .history-source-btn:hover, .challenge-type-btn:hover, .copy-btn-small:hover {
    background: rgba(255, 255, 255, 0.6) !important;
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

/* Make icon-only buttons perfectly square */
.dns-actions .btn {
    padding: 0 !important;
    width: 36px !important;
    height: 36px !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
    font-size: 1.1rem !important;
}

/* Remove gradient colors entirely */
:root {
    --ui-accent: #64748b !important;
    --ui-accent-strong: #475569 !important;
}
"""

with open('static/css/style.css', 'a', encoding='utf-8') as f:
    f.write('\n' + css)
print('Fixed record-types and other buttons!')
