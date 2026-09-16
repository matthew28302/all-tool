import re

log_path = r'C:\Users\NVX\.gemini\antigravity\brain\d157b902-77a0-4c16-8856-99a3b736fbe4\.system_generated\logs\transcript.jsonl'
with open(log_path, 'r', encoding='utf-8') as f:
    text = f.read()

html_match = re.search(r'<div id=\"tab-ai\".*?</div>\s*</div>\s*</div>\s*</div>', text, re.DOTALL)
if html_match:
    with open('ai_tab_extracted.html', 'w', encoding='utf-8') as f:
        f.write(html_match.group(0))
    print("Extracted HTML")

js_match = re.search(r'let aiChats = \[\];.*?function sendAIRequest.*?\n        }', text, re.DOTALL)
if js_match:
    with open('ai_tab_extracted.js', 'w', encoding='utf-8') as f:
        f.write(js_match.group(0))
    print("Extracted JS")
