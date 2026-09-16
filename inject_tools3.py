import re
import json

with open('app.py', 'r', encoding='utf-8') as f:
    app_py = f.read()

TOOL_DEFINITIONS = """
# --- AI TOOL CALLING DEFINITIONS ---
AI_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "tool_lookup_dns",
            "description": "Lookup DNS records for a domain (A, MX, CNAME, TXT, NS, etc.)",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "The domain name to lookup"},
                    "record_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of record types to query (e.g., ['A', 'MX', 'TXT'])"
                    }
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "tool_check_ssl",
            "description": "Check SSL/TLS certificate status for a domain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"}
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "tool_check_host",
            "description": "Lookup hosting provider and IP information for a domain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"}
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "tool_request_free_ssl",
            "description": "Start a Free SSL registration. Returns session_id and DNS TXT records needed for verification.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "sans": {
                        "type": "array",
                        "items": {"type": "string"}
                    }
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "tool_verify_free_ssl",
            "description": "Verify the DNS TXT records for a Free SSL session. Do this after the user confirms they added the TXT records.",
            "parameters": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "The SSL session_id"}
                },
                "required": ["session_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "tool_finalize_free_ssl",
            "description": "Finalize the Free SSL session and issue the certificate. Do this ONLY AFTER verification succeeds.",
            "parameters": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "The SSL session_id"}
                },
                "required": ["session_id"]
            }
        }
    }
]

def execute_ai_tool(name: str, arguments: dict) -> str:
    try:
        if name == 'tool_lookup_dns':
            domain = arguments.get('domain')
            record_types = arguments.get('record_types') or ['A', 'MX', 'CNAME', 'TXT', 'NS']
            res = check_dns_fast(domain, record_types)
            return json.dumps(res, ensure_ascii=False)
        
        elif name == 'tool_check_ssl':
            domain = arguments.get('domain')
            import socket, ssl, OpenSSL
            domain = _normalize_domain_input(domain)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert_der = ssock.getpeercert(binary_form=True)
                        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                        issuer = dict(x509.get_issuer().get_components()).get(b'O', b'').decode('utf-8')
                        not_after = x509.get_notAfter().decode('ascii')
                        return json.dumps({'issuer': issuer, 'not_after': not_after, 'status': 'success'})
            except Exception as e:
                return json.dumps({'error': str(e)})

        elif name == 'tool_check_host':
            domain = arguments.get('domain')
            domain = _normalize_domain_input(domain)
            try:
                import socket
                ip = socket.gethostbyname(domain)
                import requests
                r = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
                if r.status_code == 200:
                    return r.text
                return json.dumps({'ip': ip})
            except Exception as e:
                return json.dumps({'error': str(e)})
            
        elif name == 'tool_request_free_ssl':
            domain = arguments.get('domain')
            sans = arguments.get('sans') or []
            if domain not in sans:
                sans.insert(0, domain)
            
            client = app.test_client()
            resp = client.post('/api/ssl-free/start', json={'domain': domain, 'sans': sans, 'challenge_type': 'dns-01'})
            if resp.status_code == 200:
                data = resp.get_json()
                return json.dumps({
                    'message': 'Free SSL session started.',
                    'session_id': data.get('session_id'),
                    'challenges': data.get('challenges')
                }, ensure_ascii=False)
            else:
                return json.dumps({'error': resp.get_data(as_text=True)})
                
        elif name == 'tool_verify_free_ssl':
            session_id = arguments.get('session_id')
            client = app.test_client()
            resp = client.post('/api/ssl-free/check-challenge', json={'session_id': session_id})
            if resp.status_code == 200:
                return json.dumps(resp.get_json(), ensure_ascii=False)
            else:
                return json.dumps({'error': resp.get_data(as_text=True)})
                
        elif name == 'tool_finalize_free_ssl':
            session_id = arguments.get('session_id')
            client = app.test_client()
            resp = client.post('/api/ssl-free/finalize', json={'session_id': session_id})
            if resp.status_code == 200:
                data = resp.get_json()
                return json.dumps({
                    'message': 'SSL Certificate Issued Successfully',
                    'session_id': session_id,
                    'cert': 'Certificate details are available in the Free SSL tab. Tell the user it is completed.'
                }, ensure_ascii=False)
            else:
                return json.dumps({'error': resp.get_data(as_text=True)})
                
        else:
            return json.dumps({'error': f'Unknown tool {name}'})
            
    except Exception as e:
        logger.error(f'Tool execution error {name}: {e}')
        return json.dumps({'error': str(e)})

# --- END AI TOOL CALLING DEFINITIONS ---
"""

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
            
        system_prompt += "\\n\\nBạn là trợ lý AI có khả năng sử dụng các công cụ (tools) để tra cứu DNS, IP, SSL. Khi đăng ký SSL miễn phí, quy trình gồm 3 bước: 1) Yêu cầu SSL (tool_request_free_ssl) để lấy bản ghi TXT -> Đợi người dùng báo đã cấu hình TXT -> 2) Xác thực (tool_verify_free_ssl) -> 3) Hoàn tất và cấp chứng chỉ (tool_finalize_free_ssl)."

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
                    
                if tool_calls_buffer:
                    assistant_msg = {
                        "role": "assistant",
                        "content": None,
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
                        # Use a standard emoji character that is well-supported
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

    except Exception as exc:
        logger.error('Error in /api/ai/stream: %s', exc, exc_info=True)
        return jsonify({'error': str(exc)}), 500
"""

match = re.search(r'# --- AI TOOL CALLING DEFINITIONS ---.*?# --- END AI TOOL CALLING DEFINITIONS ---', app_py, re.DOTALL)
if match:
    app_py = app_py.replace(match.group(0), '')

match_stream = re.search(r'@app\.route\(\'/api/ai/stream\', methods=\[\'POST\'\]\)\ndef api_ai_stream\(\):.*?(?=@app\.route\(\'/api/ai/invoke\', methods=\[\'POST\'\]\))', app_py, re.DOTALL)

if match_stream:
    app_py = app_py.replace(match_stream.group(0), TOOL_DEFINITIONS + "\n\n" + NEW_STREAM + "\n\n")
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(app_py)
    print("Injected Tool Calling successfully.")
else:
    print("Could not find api_ai_stream!")

