import re
import json

with open('app.py', 'r', encoding='utf-8') as f:
    app_py = f.read()

# We need to inject the tool definitions and the tool execution logic.
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
                    "domain": {"type": "string", "description": "The domain name to lookup (e.g., example.com)"},
                    "record_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of record types to query (e.g., ['A', 'MX', 'TXT']). If empty, checks basic records."
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
                    "domain": {"type": "string", "description": "The domain name to check"}
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
                    "domain": {"type": "string", "description": "The domain name to check"}
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "tool_lookup_dns_history",
            "description": "Lookup historical DNS records for a domain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "The domain name to check"}
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "tool_request_free_ssl",
            "description": "Start a Free SSL (Let's Encrypt) registration process for a domain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "The primary domain name (e.g., example.com)"},
                    "sans": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of Subject Alternative Names, including wildcard if requested (e.g. ['*.example.com'])"
                    }
                },
                "required": ["domain"]
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
            # Reuse logic from api_check_ssl
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
                
        elif name == 'tool_lookup_dns_history':
            domain = arguments.get('domain')
            res = _fetch_mnemonic_history(domain)
            # Truncate to avoid massive context
            if 'records' in res:
                res['records'] = res['records'][:50]
            return json.dumps(res, ensure_ascii=False)
            
        elif name == 'tool_request_free_ssl':
            domain = arguments.get('domain')
            sans = arguments.get('sans') or []
            if domain not in sans:
                sans.insert(0, domain)
            
            # Start ACME flow
            sess_id = _gen_session_id()
            status = {
                'id': sess_id,
                'status': 'starting',
                'domain': domain,
                'sans': sans,
                'provider': 'letsencrypt',
                'created_at': datetime.utcnow().isoformat(),
                'logs': [{'time': datetime.utcnow().isoformat(), 'message': 'Started', 'level': 'info'}],
                'error': None,
                'challenges': []
            }
            _set_session_status(sess_id, 'starting', status)
            
            # Run background thread
            import threading
            threading.Thread(target=_run_acme_background_flow, args=(sess_id,), daemon=True).start()
            
            return json.dumps({
                'message': 'Free SSL session started in background.',
                'session_id': sess_id,
                'note': 'Tell the user that the SSL registration has started and they can view the progress in the Free SSL tab.'
            }, ensure_ascii=False)
            
        else:
            return json.dumps({'error': f'Unknown tool {name}'})
            
    except Exception as e:
        logger.error(f'Tool execution error {name}: {e}')
        return json.dumps({'error': str(e)})

# --- END AI TOOL CALLING DEFINITIONS ---
"""

# Now we need to modify api_ai_stream to handle tool calls.
# I will completely replace api_ai_stream.
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

        messages = _build_ai_messages(prompt, system_prompt, uploaded_files, history)
        
        # Limit tool calls to prevent infinite loops
        MAX_TOOL_TURNS = 3
        
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
                
                tool_calls_buffer = {} # index -> {'id': '', 'name': '', 'arguments': ''}
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
                                    
                                    # Handle content (normal text)
                                    if 'content' in delta and delta['content']:
                                        yielded_content = True
                                        yield line + b'\\n\\n'
                                        
                                    # Handle tool calls
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
                    
                # If the model called tools, we execute them and loop
                if tool_calls_buffer:
                    # Append assistant's tool call message
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
                    
                    # Execute tools and append tool messages
                    for idx, tc in tool_calls_buffer.items():
                        # Optional: yield a status message to frontend so user knows what's happening
                        yield f'data: {{"choices": [{{"delta": {{"content": "\\n\\n*🔧 Đang gọi công cụ: `{tc["name"]}`...*\\n\\n"}}}}]}}\\n\\n'.encode('utf-8')
                        
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
                    
                    # We loop again to send the tool results back to the LLM
                    continue
                else:
                    # No tool calls were made, we finished generating text.
                    break

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

# We need to replace the old api_ai_stream with the new one.
# Find where api_ai_stream starts and ends.
match = re.search(r'@app\.route\(\'/api/ai/stream\', methods=\[\'POST\'\]\)\ndef api_ai_stream\(\):.*?(?=@app\.route\(\'/api/ai/invoke\', methods=\[\'POST\'\]\))', app_py, re.DOTALL)

if match:
    old_stream = match.group(0)
    app_py = app_py.replace(old_stream, TOOL_DEFINITIONS + "\n\n" + NEW_STREAM + "\n\n")
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(app_py)
    print("Replaced api_ai_stream successfully.")
else:
    print("Could not find api_ai_stream in app.py!")

