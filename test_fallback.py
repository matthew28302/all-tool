import re, json

# Simulate what mistral-nemotron outputs
full_text = 'Dang lay chung chi SSL cho **imfishball.id.vn**...\n\n```json\n{\n  "tool": "tool_get_ssl_certificate",\n  "domain": "imfishball.id.vn"\n}\n```'

print("full_text:", repr(full_text))
print()

fb_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', full_text, re.DOTALL)
if not fb_match:
    fb_match = re.search(r'(\{\s*"tool"\s*:.*?\})', full_text, re.DOTALL)

if fb_match:
    parsed_json = json.loads(fb_match.group(1))
    tool_name = parsed_json.get('tool') or parsed_json.get('name')
    clean_args = {k: v for k, v in parsed_json.items() if k not in ('tool', 'name')}
    print(f'Tool: {tool_name}')
    print(f'Args: {json.dumps(clean_args)}')
    print('FALLBACK WORKS!')
else:
    print('FALLBACK FAILED!')
