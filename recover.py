import json
import re

with open(r'C:\Users\NVX\.gemini\antigravity\brain\d157b902-77a0-4c16-8856-99a3b736fbe4\.system_generated\logs\transcript_full.jsonl', 'r', encoding='utf-8') as f:
    for line in f:
        if 'id=\"tab-ai\"' in line:
            obj = json.loads(line)
            if obj.get('type') == 'TOOL_RESPONSE' and 'index.html' in str(obj):
                content = str(obj.get('content'))
                match = re.search(r'<div id=\"tab-ai\".*?</script>', content, re.DOTALL)
                if match:
                    print(match.group(0))
                    break
