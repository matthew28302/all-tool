import re

log_path = r'C:\Users\NVX\.gemini\antigravity\brain\d157b902-77a0-4c16-8856-99a3b736fbe4\.system_generated\logs\transcript.jsonl'
with open(log_path, 'r', encoding='utf-8') as f:
    text = f.read()

# Find any function renderAIChatList
matches = re.findall(r'function\s+renderAIChatList\s*\(\)\s*\{.*?\}', text, re.DOTALL)
if matches:
    print("Found renderAIChatList")
else:
    print("Not found")
