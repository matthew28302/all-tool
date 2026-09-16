import re

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. CSS for AI Messages
ai_css = '''
        /* AI Chat CSS */
        .ai-msg {
            padding: 16px 20px;
            border-radius: var(--radius-md);
            max-width: 85%;
            word-wrap: break-word;
            line-height: 1.6;
            animation: fadeIn 0.3s ease-out;
        }
        .ai-msg p { margin-bottom: 8px; }
        .ai-msg p:last-child { margin-bottom: 0; }
        .ai-msg pre { background: #1e293b; color: #f8fafc; padding: 12px; border-radius: 8px; overflow-x: auto; margin: 8px 0; }
        .ai-msg code { font-family: monospace; }
        .ai-msg.user {
            background: var(--primary);
            color: #ffffff;
            align-self: flex-end;
            border-bottom-right-radius: 4px;
        }
        .ai-msg.model, .ai-msg.assistant {
            background: #f1f5f9;
            color: var(--text-main);
            align-self: flex-start;
            border-bottom-left-radius: 4px;
            border: 1px solid var(--border-color);
        }
        .chat-item {
            padding: 12px;
            border-radius: var(--radius-md);
            cursor: pointer;
            margin-bottom: 8px;
            background: transparent;
            border: 1px solid transparent;
            transition: all 0.2s;
        }
        .chat-item:hover { background: #f1f5f9; }
        .chat-item.active {
            background: var(--primary-light);
            border-color: var(--primary-light);
            color: var(--primary-hover);
        }
        .chat-item-title { font-weight: 600; font-size: 0.95rem; margin-bottom: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .chat-item-meta { font-size: 0.75rem; color: var(--text-muted); }
'''
content = content.replace('</style>', ai_css + '\n</style>')

# 2. HTML
ai_html = '''
        <!-- AI Chat Tab -->
        <div id="tab-ai" class="tab-content" role="tabpanel" aria-labelledby="tabbtn-ai">
            <div class="ai-shell" style="display:flex; height: calc(100vh - 100px); gap: 20px;">
                <div class="ai-sidebar" style="width:260px; display:flex; flex-direction:column; background:var(--bg-card); border:1px solid var(--border-color); border-radius:var(--radius-md); box-shadow:var(--shadow-sm); overflow:hidden;">
                    <div style="padding: 16px; border-bottom:1px solid var(--border-color);">
                        <button class="btn btn-primary" style="width:100%;" onclick="createNewAIChat()">+ New Chat</button>
                    </div>
                    <div id="aiChatList" style="flex:1; overflow-y:auto; padding:12px;"></div>
                </div>

                <div class="ai-chat-pane" style="flex:1; display:flex; flex-direction:column; background:var(--bg-card); border-radius:var(--radius-md); box-shadow:var(--shadow-sm); overflow:hidden; border:1px solid var(--border-color);">
                    <div class="ai-chat-header" style="padding:16px; border-bottom:1px solid var(--border-color); display:flex; gap:16px; align-items:center; background:#f8fafc;">
                        <select id="aiProvider" style="padding:8px 12px; border-radius:var(--radius-md); border:1px solid var(--border-color); outline:none;">
                            <option value="nvidia">Nvidia NIM</option>
                            <option value="custom">Custom</option>
                        </select>
                        <input type="text" id="aiModel" placeholder="Model (e.g. meta/llama-3.3-70b-instruct)" value="meta/llama-3.3-70b-instruct" style="flex:1; padding:8px 12px; border:1px solid var(--border-color); border-radius:var(--radius-md); outline:none;">
                    </div>
                    
                    <div id="aiChatContainer" style="flex:1; padding:24px; overflow-y:auto; display:flex; flex-direction:column; gap:16px;">
                    </div>

                    <div class="ai-input-area" style="padding:16px; border-top:1px solid var(--border-color); display:flex; flex-direction:column; gap:12px; background:#f8fafc;">
                        <textarea id="aiInput" placeholder="Type your message..." style="width:100%; min-height:60px; padding:12px; border-radius:var(--radius-md); border:1px solid var(--border-color); outline:none; resize:vertical; font-family:var(--font-sans);" onkeydown="if(event.key==='Enter' && !event.shiftKey){event.preventDefault(); sendAIRequest();}"></textarea>
                        <div style="display:flex; justify-content:flex-end; gap:8px;">
                            <button class="btn btn-secondary" id="stopAIBtn" onclick="stopAIRequest()" style="display:none;">Stop</button>
                            <button class="btn btn-primary" id="sendAIBtn" onclick="sendAIRequest()">Send 🚀</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
'''
content = content.replace('</main></div>', ai_html + '\n</main></div>')

# 3. JS
ai_js = '''
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <script>
        let aiChats = JSON.parse(localStorage.getItem('aiChats') || '[]');
        let aiActiveChatId = null;
        let aiAbortController = null;

        function saveAIChats() {
            localStorage.setItem('aiChats', JSON.stringify(aiChats));
            renderAIChatList();
        }

        function createNewAIChat() {
            const newChat = {
                id: Date.now().toString(),
                title: 'New Conversation',
                messages: [],
                updatedAt: Date.now()
            };
            aiChats.unshift(newChat);
            aiActiveChatId = newChat.id;
            saveAIChats();
            renderAIMessages();
        }

        function loadAIChat(id) {
            aiActiveChatId = id;
            renderAIChatList();
            renderAIMessages();
        }

        function renderAIChatList() {
            const list = document.getElementById('aiChatList');
            list.innerHTML = '';
            const fragment = document.createDocumentFragment();
            aiChats.sort((a,b) => b.updatedAt - a.updatedAt).forEach(chat => {
                const item = document.createElement('div');
                item.className = 'chat-item ' + (chat.id === aiActiveChatId ? 'active' : '');
                
                const title = document.createElement('div');
                title.className = 'chat-item-title';
                title.textContent = chat.title || 'New Conversation';
                
                const meta = document.createElement('div');
                meta.className = 'chat-item-meta';
                meta.textContent = new Date(chat.updatedAt).toLocaleString();
                
                item.appendChild(title);
                item.appendChild(meta);
                item.onclick = () => loadAIChat(chat.id);
                fragment.appendChild(item);
            });
            list.appendChild(fragment);
        }

        function renderAIMessages() {
            const container = document.getElementById('aiChatContainer');
            container.innerHTML = '';
            const currentChat = aiChats.find(c => c.id === aiActiveChatId);
            if (!currentChat) return;
            
            const fragment = document.createDocumentFragment();
            currentChat.messages.forEach(msg => {
                const b = document.createElement('div');
                b.className = 'ai-msg ' + msg.role;
                let text = msg.content || '';
                text = text.replace(/<think>[\\s\\S]*?<\\/think>/g, '');
                b.innerHTML = marked.parse(text);
                fragment.appendChild(b);
            });
            container.appendChild(fragment);
            container.scrollTop = container.scrollHeight;
        }

        async function sendAIRequest() {
            const inputEl = document.getElementById('aiInput');
            const text = inputEl.value.trim();
            if(!text) return;
            
            if(!aiActiveChatId || !aiChats.find(c=>c.id === aiActiveChatId)){
                createNewAIChat();
            }
            const currentChat = aiChats.find(c => c.id === aiActiveChatId);
            if(currentChat.messages.length === 0) {
                currentChat.title = text.substring(0, 30) + '...';
            }
            
            currentChat.messages.push({role: 'user', content: text});
            currentChat.updatedAt = Date.now();
            inputEl.value = '';
            saveAIChats();
            renderAIMessages();
            
            currentChat.messages.push({role: 'assistant', content: ''});
            const msgIndex = currentChat.messages.length - 1;
            
            document.getElementById('sendAIBtn').style.display = 'none';
            document.getElementById('stopAIBtn').style.display = 'block';
            
            aiAbortController = new AbortController();
            
            try {
                const formData = new FormData();
                formData.append('provider', document.getElementById('aiProvider').value);
                formData.append('model', document.getElementById('aiModel').value);
                formData.append('messages', JSON.stringify(currentChat.messages.slice(0, -1)));
                
                const response = await fetch('/api/ai/stream', {
                    method: 'POST',
                    body: formData,
                    signal: aiAbortController.signal
                });
                
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                
                while(true) {
                    const {done, value} = await reader.read();
                    if(done) break;
                    const chunk = decoder.decode(value);
                    const lines = chunk.split('\\n');
                    for(const line of lines) {
                        if(line.startsWith('data: ')) {
                            const dataText = line.substring(6);
                            if(dataText === '[DONE]') break;
                            currentChat.messages[msgIndex].content += dataText;
                            if(currentChat.id === aiActiveChatId) {
                                renderAIMessages();
                            }
                        }
                    }
                }
            } catch(e) {
                if(e.name !== 'AbortError') {
                    currentChat.messages[msgIndex].content += "\\n\\n**Error:** " + e.message;
                }
            } finally {
                currentChat.updatedAt = Date.now();
                saveAIChats();
                document.getElementById('sendAIBtn').style.display = 'block';
                document.getElementById('stopAIBtn').style.display = 'none';
                if(currentChat.id === aiActiveChatId) renderAIMessages();
            }
        }
        
        function stopAIRequest() {
            if(aiAbortController) aiAbortController.abort();
        }

        // Initialize
        renderAIChatList();
        if(aiChats.length > 0) {
            loadAIChat(aiChats[0].id);
        }
    </script>
'''

content = content.replace('</body>', ai_js + '\n</body>')

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'w', encoding='utf-8') as f:
    f.write(content)
print('AI Chat Rebuilt Successfully.')
