import re

# 1. Fix tab_ai.html
with open('templates/tabs/tab_ai.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Fix placeholder having HTML tag
html = html.replace('placeholder="<span class=\\"icon\\" data-lucide=\\"search\\"></span> Tìm kiếm Model..."', 'placeholder="Tìm kiếm Model..."')

# Fix inline styles for buttons
html = re.sub(r'background:#4f46e5; border:none;', '', html)
html = re.sub(r'style="height:40px; padding:0 16px; border-radius:8px; font-weight:700; font-size:0.9rem; display:flex; align-items:center; gap:6px;"', '', html)
html = re.sub(r'style="height:40px; padding:0 12px; border-radius:8px; font-weight:600; display:flex; align-items:center; gap:6px;"', '', html)

# Replace remaining emojis with lucide icons in tab_ai.html
ai_emoji_map = {
    '💬': '<span class="icon" data-lucide="message-square"></span>',
    '🤖': '<span class="icon" data-lucide="bot"></span>',
    '⚡': '<span class="icon" data-lucide="zap"></span>',
    '🔄': '<span class="icon" data-lucide="refresh-cw"></span>',
    '🌟': '<span class="icon" data-lucide="star"></span>',
    '🧠': '<span class="icon" data-lucide="brain"></span>',
    '🪄': '<span class="icon" data-lucide="wand-2"></span>'
}
for emoji, icon in ai_emoji_map.items():
    html = html.replace(emoji, icon)

with open('templates/tabs/tab_ai.html', 'w', encoding='utf-8') as f:
    f.write(html)


# 2. Fix style.css for .ai-tab-btn, .ai-prompt-btn
with open('static/css/style.css', 'r', encoding='utf-8') as f:
    css = f.read()

# Append fixes to style.css
new_css = """
/* 7. AI Chat Specific Resets */
.ai-tab-btn {
    color: #64748b !important;
    background: transparent !important;
}
.ai-tab-btn:hover {
    background: rgba(15,23,42,0.04) !important;
}
.ai-tab-btn.active {
    background: #ffffff !important;
    color: #0f172a !important;
    font-weight: 600 !important;
    box-shadow: 0 2px 6px rgba(15, 23, 42, 0.04) !important;
}
.ai-tab-btn .icon, .ai-tab-btn.active .icon {
    color: #64748b !important; 
}
.ai-prompt-btn, .ai-icon-btn, .dns-view-switch button {
    background: #ffffff !important;
    color: #475569 !important;
    border: 1px solid #cbd5e1 !important;
}
.ai-prompt-btn:hover, .ai-icon-btn:hover {
    background: #f1f5f9 !important;
    color: #0f172a !important;
    border-color: #94a3b8 !important;
}
"""

with open('static/css/style.css', 'a', encoding='utf-8') as f:
    f.write(new_css)

# 3. Bust cache in index.html
with open('templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()
import time
ts = int(time.time())
content = re.sub(r'filename=\'css/style\.css\'\)\s*\}\}\?v=\d+', f'filename=\'css/style.css\') }}?v={ts}', content)
with open('templates/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print('Fixed AI Chat tab!')
