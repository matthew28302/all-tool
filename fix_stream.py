import re

with open('app.py', 'r', encoding='utf-8') as f:
    code = f.read()

# Find the generate_sse function and everything up to and including the Response return
# Pattern: from "def generate_sse():" up to just before "return Response("
old_pattern = re.compile(
    r'(        def generate_sse\(\):.*?)(\n        return Response\()',
    re.DOTALL
)

match = old_pattern.search(code)
if not match:
    print("ERROR: Could not find generate_sse function!")
    exit(1)

print(f"Found generate_sse at position {match.start()}-{match.end()}")

NEW_GENERATE_SSE = '''        def generate_sse():
            nonlocal messages
            turn_count = 0
            use_tools = True  # Disable after fallback to avoid infinite loop
            
            while turn_count <= MAX_TOOL_TURNS:
                turn_count += 1
                
                payload = {
                    'model': model,
                    'messages': messages,
                    'temperature': 0.7,
                    'max_tokens': 4096,
                    'stream': True,
                }
                if use_tools:
                    payload['tools'] = AI_TOOLS
                    payload['tool_choice'] = 'auto'

                headers = {
                    'Authorization': f'Bearer {target_key}',
                    'Content-Type': 'application/json',
                }
                endpoint = f"{target_base.rstrip('/')}/chat/completions"
                
                try:
                    req = _ai_session.post(endpoint, headers=headers, json=payload, stream=True, timeout=(5, 120))
                except Exception as req_err:
                    yield f'data: {{"choices": [{{"delta": {{"content": "\\\\n\\\\n[Loi ket noi: {req_err}]"}}}}]}}\\n\\n'.encode('utf-8')
                    return
                
                if req.status_code >= 400:
                    err_text = req.text
                    yield f'data: {{"choices": [{{"delta": {{"content": "\\\\n\\\\n[API Error {req.status_code}: {err_text}]"}}}}]}}\\n\\n'.encode('utf-8')
                    return
                
                native_tool_calls = {}
                full_text = ''
                raw_lines = []  # Buffer SSE lines
                
                try:
                    for line in req.iter_lines():
                        if line:
                            line_str = line.decode('utf-8').strip()
                            if line_str.startswith('data: '):
                                data_str = line_str[6:]
                                if data_str == '[DONE]':
                                    continue
                                try:
                                    chunk = json.loads(data_str)
                                    delta = chunk['choices'][0].get('delta', {})
                                    
                                    if 'content' in delta and delta['content']:
                                        full_text += delta['content']
                                        raw_lines.append(line)
                                        
                                    if 'tool_calls' in delta:
                                        for tc in delta['tool_calls']:
                                            idx = tc['index']
                                            if idx not in native_tool_calls:
                                                native_tool_calls[idx] = {'id': tc.get('id', ''), 'name': '', 'arguments': ''}
                                            if 'id' in tc and tc['id']:
                                                native_tool_calls[idx]['id'] = tc['id']
                                            if 'function' in tc:
                                                if 'name' in tc['function'] and tc['function']['name']:
                                                    native_tool_calls[idx]['name'] += tc['function']['name']
                                                if 'arguments' in tc['function'] and tc['function']['arguments']:
                                                    native_tool_calls[idx]['arguments'] += tc['function']['arguments']
                                                    
                                except json.JSONDecodeError:
                                    pass
                except Exception as stream_err:
                    yield f'data: {{"choices": [{{"delta": {{"content": "\\\\n\\\\n[Loi stream: {stream_err}]"}}}}]}}\\n\\n'.encode('utf-8')
                    return
                
                # === CASE 1: Native tool calls (model properly supports function calling) ===
                if native_tool_calls:
                    assistant_msg = {"role": "assistant", "content": full_text if full_text else None, "tool_calls": []}
                    for idx, tc in native_tool_calls.items():
                        assistant_msg["tool_calls"].append({
                            "id": tc['id'], "type": "function",
                            "function": {"name": tc['name'], "arguments": tc['arguments']}
                        })
                    messages.append(assistant_msg)
                    
                    for idx, tc in native_tool_calls.items():
                        status_msg = f"\\\\n\\\\n*Dang goi: `{tc['name']}`...*\\\\n\\\\n"
                        yield f'data: {{"choices": [{{"delta": {{"content": "{status_msg}"}}}}]}}\\n\\n'.encode('utf-8')
                        try:
                            args_dict = json.loads(tc['arguments'])
                        except json.JSONDecodeError:
                            args_dict = {}
                        result_str = execute_ai_tool(tc['name'], args_dict)
                        messages.append({"role": "tool", "tool_call_id": tc['id'], "name": tc['name'], "content": result_str})
                    continue
                
                # === CASE 2: No native tool calls - check fallback JSON in text ===
                if use_tools and full_text:
                    fb_match = re.search(r'```(?:json)?\\s*(\\{.*?\\})\\s*```', full_text, re.DOTALL)
                    if not fb_match:
                        fb_match = re.search(r'(\\{\\s*"tool"\\s*:.*?\\})', full_text, re.DOTALL)
                    if fb_match:
                        try:
                            parsed_json = json.loads(fb_match.group(1))
                            tool_name = parsed_json.get('tool') or parsed_json.get('name')
                            if tool_name and tool_name.startswith('tool_'):
                                clean_args = {k: v for k, v in parsed_json.items() if k not in ('tool', 'name')}
                                
                                # DON'T yield the buffered text (it contains ugly JSON)
                                status_msg = f"\\\\n\\\\n*Dang goi: `{tool_name}`...*\\\\n\\\\n"
                                yield f'data: {{"choices": [{{"delta": {{"content": "{status_msg}"}}}}]}}\\n\\n'.encode('utf-8')
                                
                                result_str = execute_ai_tool(tool_name, clean_args)
                                
                                # Send result as USER message (model doesn't support role:tool)
                                messages.append({"role": "assistant", "content": full_text})
                                messages.append({
                                    "role": "user",
                                    "content": f"[KET QUA TU CONG CU {tool_name}]:\\n{result_str}\\n\\nHay phan tich ket qua tren va tra loi nguoi dung. Neu co certificate/private_key, hay hien thi nguyen van noi dung."
                                })
                                
                                use_tools = False  # Prevent infinite loop
                                continue
                        except Exception as fb_err:
                            logger.warning(f'Fallback tool parse error: {fb_err}')
                
                # === CASE 3: Normal text response - yield buffered content ===
                for raw_line in raw_lines:
                    yield raw_line + b'\\n\\n'
                break
                
            if turn_count > MAX_TOOL_TURNS:
                yield f'data: {{"choices": [{{"delta": {{"content": "\\\\n\\\\n*Vuot qua so lan goi cong cu.*\\\\n\\\\n"}}}}]}}\\n\\n'.encode('utf-8')
'''

code = code[:match.start()] + NEW_GENERATE_SSE + "\n" + code[match.start() + len(match.group(1)):]

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(code)

print("SUCCESS: Replaced generate_sse function.")
