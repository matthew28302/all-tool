import re

css_append = """
/* 8. Premium Select Style for AI Chat */
.ai-premium-select {
    appearance: none;
    -webkit-appearance: none;
    -moz-appearance: none;
    background-color: #ffffff !important;
    border: 1px solid #cbd5e1 !important;
    border-radius: 12px !important;
    padding: 10px 40px 10px 16px !important;
    font-size: 0.95rem !important;
    font-weight: 500 !important;
    color: #1e293b !important;
    height: 44px !important;
    width: 100% !important;
    box-sizing: border-box !important;
    transition: all 0.2s ease !important;
    box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03) !important;
    background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e") !important;
    background-repeat: no-repeat !important;
    background-position: right 14px center !important;
    background-size: 16px !important;
    cursor: pointer !important;
}

.ai-premium-select:hover {
    border-color: #94a3b8 !important;
    box-shadow: 0 2px 5px rgba(15, 23, 42, 0.06) !important;
}

.ai-premium-select:focus {
    border-color: #64748b !important;
    box-shadow: 0 0 0 4px rgba(100, 116, 139, 0.1) !important;
    outline: none !important;
}
"""

with open('static/css/style.css', 'a', encoding='utf-8') as f:
    f.write(css_append)

with open('templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

import time
ts = int(time.time())
content = re.sub(r'filename=\'css/style\.css\'\)\s*\}\??v=\d+', 'filename=\'css/style.css\') }}?v=' + str(ts), content)

with open('templates/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("Appended premium select css and busted cache")
