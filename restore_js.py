import re

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'r', encoding='utf-8') as f:
    c = f.read()

# 1. Re-implement renderAIChatList with DocumentFragment
render_ai_old = '''function renderAIChatList() {
            const list = document.getElementById('aiChatList');
            list.innerHTML = '';
            
            aiChats.sort((a,b) => b.updatedAt - a.updatedAt).forEach(chat => {
                const item = document.createElement('div');
                item.className = 'chat-item ' + (chat.id === aiActiveChatId ? 'active' : '');
                
                const title = document.createElement('div');
                title.className = 'chat-item-title';
                title.textContent = chat.title;
                
                const meta = document.createElement('div');
                meta.className = 'chat-item-meta';
                meta.textContent = new Date(chat.updatedAt).toLocaleString();
                
                const delBtn = document.createElement('button');
                delBtn.className = 'chat-item-delete';
                delBtn.innerHTML = '🗑️';
                delBtn.onclick = (e) => {
                    e.stopPropagation();
                    deleteAIChat(chat.id);
                };
                
                item.appendChild(title);
                item.appendChild(meta);
                item.appendChild(delBtn);
                
                item.onclick = () => loadAIChat(chat.id);
                list.appendChild(item);
            });
        }'''

render_ai_new = '''function renderAIChatList() {
            const list = document.getElementById('aiChatList');
            list.innerHTML = '';
            
            const fragment = document.createDocumentFragment();
            aiChats.sort((a,b) => b.updatedAt - a.updatedAt).forEach(chat => {
                const item = document.createElement('div');
                item.className = 'chat-item ' + (chat.id === aiActiveChatId ? 'active' : '');
                
                const title = document.createElement('div');
                title.className = 'chat-item-title';
                title.textContent = chat.title;
                
                const meta = document.createElement('div');
                meta.className = 'chat-item-meta';
                meta.textContent = new Date(chat.updatedAt).toLocaleString();
                
                const delBtn = document.createElement('button');
                delBtn.className = 'chat-item-delete';
                delBtn.innerHTML = '🗑️';
                delBtn.onclick = (e) => {
                    e.stopPropagation();
                    deleteAIChat(chat.id);
                };
                
                item.appendChild(title);
                item.appendChild(meta);
                item.appendChild(delBtn);
                
                item.onclick = () => loadAIChat(chat.id);
                fragment.appendChild(item);
            });
            list.appendChild(fragment);
        }'''
c = c.replace(render_ai_old, render_ai_new)

# 2. Re-implement <think> tag strip and rendering
# The scheduleUIUpdate or renderAIMessages function
render_msgs_old = '''function renderAIMessages() {
            const container = document.getElementById('aiChatContainer');
            container.innerHTML = '';
            
            const currentChat = aiChats.find(c => c.id === aiActiveChatId);
            if (!currentChat) return;
            
            currentChat.messages.forEach(msg => {
                const b = document.createElement('div');
                b.className = 'ai-msg ' + msg.role;
                b.innerHTML = marked.parse(msg.content || '');
                container.appendChild(b);
            });
            
            container.scrollTop = container.scrollHeight;
        }'''
        
render_msgs_new = '''function renderAIMessages() {
            const container = document.getElementById('aiChatContainer');
            container.innerHTML = '';
            
            const currentChat = aiChats.find(c => c.id === aiActiveChatId);
            if (!currentChat) return;
            
            const fragment = document.createDocumentFragment();
            currentChat.messages.forEach(msg => {
                const b = document.createElement('div');
                b.className = 'ai-msg ' + msg.role;
                let text = msg.content || '';
                text = text.replace(/<think>[\\s\\S]*?<\\/think>/g, ''); // strip think tags
                b.innerHTML = marked.parse(text);
                fragment.appendChild(b);
            });
            
            container.appendChild(fragment);
            container.scrollTop = container.scrollHeight;
        }'''
c = c.replace(render_msgs_old, render_msgs_new)

# 3. aiActiveChatId check inside sendAIRequest
# Search for the SSE loop inside sendAIRequest
sse_loop_old = '''currentChat.messages[msgIndex].content += text;
                        renderAIMessages();'''

sse_loop_new = '''currentChat.messages[msgIndex].content += text;
                        if (currentChat.id === aiActiveChatId) {
                            renderAIMessages();
                        }'''
c = c.replace(sse_loop_old, sse_loop_new)

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'w', encoding='utf-8') as f:
    f.write(c)
print('JS patches restored.')
