import re

with open('app.py', 'r', encoding='utf-8') as f:
    app_py = f.read()

match_stream = re.search(r'@app\.route\(\'/api/ai/stream\', methods=\[\'POST\'\]\)\ndef api_ai_stream\(\):.*?(?=@app\.route\(\'/api/ai/invoke\', methods=\[\'POST\'\]\))', app_py, re.DOTALL)

if not match_stream:
    print("Could not find stream route!")
    exit(1)
    
NEW_STREAM = """
@app.route('/api/ai/stream', methods=['POST'])
def api_ai_stream():
    try:
        provider = (request.form.get('provider') or 'nvidia').strip().lower()
        api_key = (request.form.get('api_key') or '').strip()
        api_base = (request.form.get('api_base') or '').strip()

        if provider == 'nvidia':
            target_key = api_key or NVIDIA_NIM_API_KEY
            target_base = api_base or NVIDIA_NIM_API_BASE
            default_model = 'meta/llama-3.3-70b-instruct'
        elif provider == 'custom':
            target_key = api_key
            target_base = api_base or 'https://api.openai.com/v1'
            default_model = 'gpt-3.5-turbo'
        else:
            target_key = AI_API_KEY
            target_base = AI_API_BASE
            default_model = AI_MODELS[0]

        prompt = (request.form.get('prompt') or '').strip()
        system_prompt = (request.form.get('system_prompt') or '').strip()
        model = (request.form.get('model') or default_model).strip()
        history_raw = (request.form.get('history') or '').strip()

        history = []
        if history_raw:
            try:
                history = json.loads(history_raw) or []
            except Exception:
                history = []

        uploaded_files = []
        for upload in request.files.getlist('files'):
            item = _read_uploaded_ai_file(upload)
            if item:
                uploaded_files.append(item)

        if not prompt and not uploaded_files:
            return jsonify({'error': 'Vui lòng nhập prompt hoặc đính kèm tệp.'}), 400

        if not system_prompt:
            system_prompt = DEFAULT_AI_SYSTEM_PROMPT
            
        system_prompt += "\\n\\n[CHÚ Ý QUAN TRỌNG: Bạn là trợ lý AI có khả năng sử dụng CÔNG CỤ (TOOLS). Khi người dùng yêu cầu kiểm tra DNS, SSL, IP, cấp phát SSL... BẠN BẮT BUỘC PHẢI GỌI TOOL NGAY LẬP TỨC. KHÔNG ĐƯỢC chỉ trả lời suông là 'Tôi đang kiểm tra...' rồi dừng lại mà không gọi Tool! QUY TRÌNH CẤP SSL MIỄN PHÍ: 1) tool_request_free_ssl (để lấy TXT yêu cầu người dùng cấu hình). 2) Khi user báo đã cấu hình TXT xong -> gọi tool_verify_free_ssl. 3) Nếu verify thành công -> GỌI NGAY tool_finalize_free_ssl để lấy Certificate và in nguyên văn đoạn Certificate ra màn hình cho người dùng!]"

        messages = _build_ai_messages(prompt, system_prompt, uploaded_files, history)
        
        MAX_TOOL_TURNS = 5
        
        def generate_sse():
            nonlocal messages
            turn_count = 0
            
            while turn_count <= MAX_TOOL_TURNS:
                turn_count += 1
                
                payload = {
                    'model': model,
                    'messages': messages,
                    'temperature': 0.7,
                    'max_tokens': 2048,
                    'stream': True,
                    'tools': AI_TOOLS,
                    'tool_choice': 'auto'
                }

                headers = {
                    'Authorization': f'Bearer {target_key}',
                    'Content-Type': 'application/json',
                }
                endpoint = f"{target_base.rstrip('/')}/chat/completions"
                
                try:
                    req = _ai_session.post(endpoint, headers=headers, json=payload, stream=True, timeout=(5, 120))
                except Exception as req_err:
                    yield f'data: {{"choices": [{{"delta": {{"content": "\\n\\n[Lỗi kết nối API AI: {req_err}]"}}}}]}}\\n\\n'.encode('utf-8')
                    return
                
                if req.status_code >= 400:
                    err_text = req.text
                    yield f'data: {{"choices": [{{"delta": {{"content": "\\n\\n[API Error {req.status_code}: {err_text}]"}}}}]}}\\n\\n'.encode('utf-8')
                    return
                
                tool_calls_buffer = {} 
                yielded_content = False
                full_text = ''
                
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
                                        yielded_content = True
                                        full_text += delta['content']
                                        yield line + b'\\n\\n'
                                        
                                    if 'tool_calls' in delta:
                                        for tc in delta['tool_calls']:
                                            idx = tc['index']
                                            if idx not in tool_calls_buffer:
                                                tool_calls_buffer[idx] = {'id': tc.get('id', ''), 'name': '', 'arguments': ''}
                                            
                                            if 'id' in tc and tc['id']:
                                                tool_calls_buffer[idx]['id'] = tc['id']
                                            if 'function' in tc:
                                                if 'name' in tc['function'] and tc['function']['name']:
                                                    tool_calls_buffer[idx]['name'] += tc['function']['name']
                                                if 'arguments' in tc['function'] and tc['function']['arguments']:
                                                    tool_calls_buffer[idx]['arguments'] += tc['function']['arguments']
                                                    
                                except json.JSONDecodeError:
                                    pass
                except Exception as stream_err:
                    yield f'data: {{"choices": [{{"delta": {{"content": "\\n\\n[Lỗi stream: {stream_err}]"}}}}]}}\\n\\n'.encode('utf-8')
                    return
                    
                # HACK: Fallback parsing for weak models (like mistral-nemotron) that output JSON block in text instead of tool_calls
                if not tool_calls_buffer and full_text:
                    match = re.search(r'```(?:json)?\\s*(\\{.*?\\})\\s*```', full_text, re.DOTALL)
                    if match:
                        try:
                            parsed_json = json.loads(match.group(1))
                            tool_name = parsed_json.get('tool') or parsed_json.get('name')
                            if tool_name and tool_name.startswith('tool_'):
                                tool_calls_buffer[0] = {
                                    'id': 'call_fallback_' + str(int(datetime.now().timestamp())),
                                    'name': tool_name,
                                    'arguments': json.dumps(parsed_json)
                                }
                        except:
                            pass
                            
                if tool_calls_buffer:
                    assistant_msg = {
                        "role": "assistant",
                        "content": full_text if full_text else None,
                        "tool_calls": []
                    }
                    for idx, tc in tool_calls_buffer.items():
                        assistant_msg["tool_calls"].append({
                            "id": tc['id'],
                            "type": "function",
                            "function": {
                                "name": tc['name'],
                                "arguments": tc['arguments']
                            }
                        })
                    messages.append(assistant_msg)
                    
                    for idx, tc in tool_calls_buffer.items():
                        yield f'data: {{"choices": [{{"delta": {{"content": "\\n\\n*⚙️ Đang gọi: `{tc["name"]}`...*\\n\\n"}}}}]}}\\n\\n'.encode('utf-8')
                        
                        try:
                            args_dict = json.loads(tc['arguments'])
                        except json.JSONDecodeError:
                            args_dict = {}
                            
                        result_str = execute_ai_tool(tc['name'], args_dict)
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc['id'],
                            "name": tc['name'],
                            "content": result_str
                        })
                    continue
                else:
                    break
                    
            if not yielded_content and not tool_calls_buffer and turn_count > MAX_TOOL_TURNS:
                yield f'data: {{"choices": [{{"delta": {{"content": "\\n\\n*⚠️ AI đã vượt quá số lần gọi công cụ cho phép.*\\n\\n"}}}}]}}\\n\\n'.encode('utf-8')

        return Response(
            stream_with_context(generate_sse()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
                'Connection': 'keep-alive',
            }
        )
"""

app_py = app_py.replace(match_stream.group(0), NEW_STREAM + "\n")
with open('app.py', 'w', encoding='utf-8') as f:
    f.write(app_py)
print("Added fallback JSON parser.")
