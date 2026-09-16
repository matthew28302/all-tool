import sys

file_path = r'c:\Users\NVX\Downloads\all-tool\templates\index.html'

css_replacement = """        .ai-shell {
            display: flex;
            gap: 20px;
            align-items: stretch;
            box-sizing: border-box;
            height: calc(100vh - 120px);
            min-height: 600px;
        }
        @media (max-width: 992px) {
            .ai-shell {
                flex-direction: column;
                height: auto;
            }
        }
        .ai-sidebar {
            width: 280px;
            flex-shrink: 0;
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 16px;
            padding: 20px;
            box-shadow: 0 4px 15px rgba(15, 23, 42, 0.03);
            box-sizing: border-box;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }
        .ai-chat-pane {
            flex-grow: 1;
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 16px;
            box-shadow: 0 4px 15px rgba(15, 23, 42, 0.03);
            box-sizing: border-box;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            min-width: 0;
        }
        @media (max-width: 992px) {
            .ai-sidebar {
                width: 100%;
                max-height: 300px;
            }
            .ai-chat-pane {
                height: 800px;
            }
        }
        .ai-sidebar-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 16px;
        }
        .ai-history-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
            overflow-y: auto;
            flex: 1;
        }
        .ai-history-item {
            border: 1px solid transparent;
            border-radius: 12px;
            padding: 12px;
            background: #f8fafc;
            cursor: pointer;
            text-align: left;
            transition: all 0.2s ease;
        }
        .ai-history-item:hover {
            background: #f1f5f9;
        }
        .ai-history-item.active {
            border-color: #0ea5e9;
            background: #e0f2fe;
            box-shadow: 0 2px 8px rgba(14, 165, 233, 0.1);
        }
        .ai-history-title {
            font-weight: 700;
            color: #0f172a;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-size: 0.9rem;
        }
        .ai-history-meta {
            font-size: 0.75rem;
            color: #64748b;
            margin-top: 4px;
        }
        .ai-chat-header {
            padding: 20px;
            border-bottom: 1px solid #e2e8f0;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #ffffff;
            flex-wrap: wrap;
            gap: 12px;
        }
        .ai-provider-bar {
            background: #f8fafc;
            border-bottom: 1px solid #e2e8f0;
            padding: 16px 20px;
            display: flex;
            flex-direction: column;
            gap: 16px;
            box-sizing: border-box;
        }
        .ai-provider-row {
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            align-items: flex-end;
            width: 100%;
        }
        .ai-provider-row > div:nth-child(1) {
            flex: 1 1 200px;
        }
        .ai-provider-row > div:nth-child(2) {
            flex: 2 1 250px;
            min-width: 0;
        }
        .ai-provider-row > div:nth-child(3) {
            flex: 0 0 auto;
            display: flex;
            gap: 10px;
        }
        .ai-filter-row {
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            align-items: center;
            border-top: 1px solid #e2e8f0;
            padding-top: 16px;
            width: 100%;
        }
        .ai-filter-row > div:first-child {
            flex: 1 1 250px;
            min-width: 0;
        }
        .ai-filter-row > div:last-child {
            flex: 2 1 auto;
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
        }
        .ai-presets-row {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
            width: 100%;
        }
        .ai-prompt-btn, .ai-icon-btn {
            border: 1px solid #cbd5e1;
            background: #ffffff;
            color: #334155;
            border-radius: 999px;
            padding: 6px 14px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .ai-prompt-btn:hover, .ai-icon-btn:hover {
            background: #f1f5f9;
        }
        .ai-prompt-btn.active, .ai-icon-btn.active {
            background: #0ea5e9;
            color: #fff;
            border-color: #0ea5e9;
        }
        .ai-prompt-panel {
            display: none;
            padding: 16px 20px;
            border-bottom: 1px solid #e2e8f0;
            background: #f8fafc;
            box-sizing: border-box;
        }
        .ai-prompt-panel.show { display: block; }
        .ai-prompt-panel textarea {
            width: 100%;
            min-height: 100px;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            padding: 12px;
            font: inherit;
            resize: vertical;
            box-sizing: border-box;
            background: #ffffff;
        }
        .ai-chat-messages {
            display: flex;
            flex-direction: column;
            gap: 20px;
            flex-grow: 1;
            overflow-y: auto;
            padding: 20px;
            background: #ffffff;
            scroll-behavior: smooth;
        }
        .ai-chat-messages::-webkit-scrollbar {
            width: 6px;
        }
        .ai-chat-messages::-webkit-scrollbar-thumb {
            background-color: #cbd5e1;
            border-radius: 10px;
        }
        .ai-chat-bubble {
            border-radius: 16px;
            padding: 12px 16px;
            max-width: 85%;
            white-space: pre-wrap;
            word-break: break-word;
            line-height: 1.5;
            font-size: 0.95rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }
        .ai-chat-bubble.user {
            background: #0ea5e9;
            color: #fff;
            margin-left: auto;
            border-bottom-right-radius: 4px;
        }
        .ai-chat-bubble.assistant {
            background: #f1f5f9;
            border: 1px solid #e2e8f0;
            color: #1e293b;
            margin-right: auto;
            border-bottom-left-radius: 4px;
        }
        .ai-chat-bubble .meta {
            font-size: 0.75rem;
            opacity: 0.8;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .ai-composer {
            border-top: 1px solid #e2e8f0;
            padding: 16px 20px;
            background: #ffffff;
            display: flex;
            flex-direction: column;
            gap: 12px;
            box-sizing: border-box;
        }
        .ai-composer textarea {
            width: 100%;
            min-height: 60px;
            max-height: 200px;
            border: 1px solid #cbd5e1;
            border-radius: 12px;
            padding: 12px 16px;
            resize: none;
            font: inherit;
            box-sizing: border-box;
            background: #f8fafc;
            outline: none;
            font-size: 0.95rem;
            transition: all 0.2s;
        }
        .ai-composer textarea:focus {
            background: #ffffff;
            border-color: #0ea5e9;
            box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.1);
        }
        .ai-composer textarea::placeholder {
            color: #94a3b8;
        }
        .ai-compose-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
            justify-content: space-between;
        }
        .ai-compose-actions-left {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
        }
        .ai-file-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            border-radius: 999px;
            padding: 4px 10px;
            background: #e0f2fe;
            color: #0369a1;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .ai-model-chip {
            height: 30px;
            padding: 0 12px;
            border: 1px solid #cbd5e1;
            background: #ffffff;
            color: #475569;
            border-radius: 999px;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
            white-space: nowrap;
        }
        .ai-model-chip:hover, .ai-model-chip.active {
            background: #0ea5e9;
            color: #ffffff;
            border-color: #0ea5e9;
        }
        .ai-filter-tab {
            height: 30px;
            padding: 0 12px;
            border: 1px solid #cbd5e1;
            background: #ffffff;
            color: #475569;
            border-radius: 999px;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
            white-space: nowrap;
        }
        .ai-filter-tab:hover, .ai-filter-tab.active {
            background: #4f46e5;
            color: #ffffff;
            border-color: #4f46e5;
        }
        .ai-badge-active {
            display: inline-flex;
            align-items: center;
            background: #dbeafe;
            color: #1e40af;
            border: 1px solid #bfdbfe;
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 0.8rem;
            font-weight: 700;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .btn-danger {
            height: 40px;
            background: #ef4444;
            color: #ffffff;
            border: 1px solid #dc2626;
            font-weight: 700;
            padding: 0 16px;
            border-radius: 8px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
        }
        .btn-danger:hover {
            background: #dc2626;
        }
        .ai-empty {
            color: #64748b;
            padding: 32px 16px;
            border: 2px dashed #cbd5e1;
            border-radius: 12px;
            background: #f8fafc;
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 12px;
        }
        .ai-render-image {
            margin-top: 12px;
            max-width: 100%;
            border-radius: 12px;
            border: 1px solid #e2e8f0;
            box-shadow: 0 4px 16px rgba(0,0,0,0.06);
        }
"""

html_replacement = """        <div id="tab-ai" class="tab-content" role="tabpanel" aria-labelledby="tabbtn-ai" hidden style="padding:0; box-shadow:none; background:transparent;">
            <div class="ai-shell">
                <aside class="ai-sidebar" id="aiSidebar">
                    <div class="ai-sidebar-header">
                        <div class="dns-panel-title" style="margin:0; font-size:1.1rem;">💬 Chat History</div>
                        <button class="ai-prompt-btn" style="padding:4px 10px;" onclick="createNewAIChat()">+ mới</button>
                    </div>
                    <div id="aiHistoryList" class="ai-history-list"></div>
                </aside>

                <div class="ai-chat-pane">
                    <div class="ai-chat-header">
                        <div style="display:flex; flex-direction:column; gap:6px;">
                            <div class="dns-panel-title" style="display:flex; align-items:center; gap:10px; margin:0;">
                                🤖 AI Chat (Streaming)
                                <span id="aiActiveModelBadge" class="ai-badge-active" title="Model đang sử dụng">meta/llama-3.3-70b-instruct</span>
                            </div>
                            <div class="dns-panel-subtitle" style="margin:0;">Khảo sát tốc độ song song, ngắt kết nối trực tiếp & phản hồi thời gian thực.</div>
                        </div>
                        <div style="display:flex; gap:8px;">
                            <button class="ai-prompt-btn" type="button" onclick="deleteActiveAIChat()" title="Xoá đoạn chat hiện tại">🗑️ Xóa</button>
                            <button class="ai-prompt-btn" id="aiPromptToggle" type="button" onclick="toggleAIPromptPanel()">⚙️ Cấu hình</button>
                        </div>
                    </div>

                    <!-- AI Config & Model Control Center -->
                    <div class="ai-provider-bar">
                        <!-- Row 1: Provider, Model Select, Actions -->
                        <div class="ai-provider-row">
                            <div style="display:flex; flex-direction:column; gap:6px;">
                                <label style="font-size:0.85rem; font-weight:700; color:#334155;">Nhà cung cấp:</label>
                                <select id="aiProviderSelect" class="dns-input" style="height:40px; padding:0 12px; font-size:0.9rem; border-radius:8px;" onchange="onAIProviderChange()">
                                    <option value="nvidia" selected>⚡ NVIDIA NIM</option>
                                    <option value="agnes">🤖 Agnes AI</option>
                                    <option value="custom">⚙️ Custom API</option>
                                </select>
                            </div>

                            <div style="display:flex; flex-direction:column; gap:6px; min-width:0;">
                                <label style="font-size:0.85rem; font-weight:700; color:#334155; display:flex; justify-content:space-between;">
                                    <span>Model AI (<span id="aiModelCount">Đang tải...</span>):</span>
                                </label>
                                <select id="aiModelSelect" class="dns-input" style="height:40px; padding:0 12px; font-size:0.9rem; border-radius:8px; text-overflow:ellipsis;" onchange="onAIModelSelectChange()">
                                    <option value="meta/llama-3.3-70b-instruct">meta/llama-3.3-70b-instruct</option>
                                </select>
                            </div>

                            <div style="display:flex; gap:8px; align-items:flex-end;">
                                <button type="button" class="btn btn-primary" style="height:40px; padding:0 16px; background:#4f46e5; border:none; border-radius:8px; font-weight:700; font-size:0.9rem; display:flex; align-items:center; gap:6px;" id="aiTestSpeedBtn" onclick="testAllModelsSpeed()">
                                    <span>⚡</span> Kiểm thử (Song song)
                                </button>
                                <button type="button" class="btn btn-secondary" style="height:40px; padding:0 12px; border-radius:8px; font-weight:600; display:flex; align-items:center; gap:6px;" onclick="loadAIModels(true)">
                                    <span>🔄</span> Reload
                                </button>
                            </div>
                        </div>

                        <!-- Row 2: Search Input & Speed Filters -->
                        <div class="ai-filter-row">
                            <div>
                                <input type="text" id="aiModelSearchInput" class="dns-input" style="height:38px; padding:0 12px; font-size:0.9rem; border-radius:8px; width:100%; box-sizing:border-box;" placeholder="🔍 Tìm kiếm Model..." oninput="filterAIModels()">
                            </div>

                            <div style="display:flex; flex-wrap:wrap; gap:8px; align-items:center;">
                                <span style="font-size:0.85rem; font-weight:700; color:#64748b;">Phân loại:</span>
                                <button type="button" class="ai-filter-tab active" data-speed="all" onclick="setAISpeedFilter('all', this)">Tất cả</button>
                                <button type="button" class="ai-filter-tab" data-speed="fast" onclick="setAISpeedFilter('fast', this)">🚀 Nhanh</button>
                                <button type="button" class="ai-filter-tab" data-speed="medium" onclick="setAISpeedFilter('medium', this)">⚡ T.Bình</button>
                                <button type="button" class="ai-filter-tab" data-speed="slow" onclick="setAISpeedFilter('slow', this)">🐢 Chậm</button>
                                <button type="button" class="ai-filter-tab" data-speed="working" onclick="setAISpeedFilter('working', this)">🛡️ Hoạt động</button>
                            </div>
                        </div>

                        <!-- Row 3: Presets -->
                        <div class="ai-presets-row">
                            <span style="font-size:0.85rem; font-weight:700; color:#64748b;">Gợi ý:</span>
                            <button type="button" class="ai-model-chip" onclick="selectAIModel('meta/llama-3.3-70b-instruct')">⚡ Llama 3.3 70B</button>
                            <button type="button" class="ai-model-chip" onclick="selectAIModel('deepseek-ai/deepseek-r1')">🔥 DeepSeek R1</button>
                            <button type="button" class="ai-model-chip" onclick="selectAIModel('nvidia/llama-3.1-nemotron-70b-instruct')">🤖 Nemotron 70B</button>
                            <button type="button" class="ai-model-chip" onclick="selectAIModel('mistralai/mistral-large-2-instruct')">💨 Mistral Large 2</button>
                            <button type="button" class="ai-model-chip" onclick="selectAIModel('qwen/qwen2.5-72b-instruct')">🌟 Qwen 2.5 72B</button>
                        </div>

                        <div id="aiTestStatusProgress" style="display:none; margin-top:8px; background:#e0e7ff; color:#3730a3; padding:12px 16px; border-radius:12px; font-size:0.9rem; font-weight:600; text-align:center;">
                            ⚡ Đang kiểm thử kết nối song song...
                        </div>

                        <div id="aiCustomKeyBlock" style="display:none; margin-top:8px;">
                            <div style="display:flex; gap:12px; flex-wrap:wrap;">
                                <input type="text" id="aiApiKeyInput" class="dns-input" style="flex:1; min-width:200px; padding:10px 12px; font-size:0.9rem; border-radius:8px;" placeholder="API Key" onchange="saveAIKeyConfig()">
                                <input type="text" id="aiApiBaseInput" class="dns-input" style="flex:1; min-width:200px; padding:10px 12px; font-size:0.9rem; border-radius:8px;" placeholder="API Base URL" onchange="saveAIKeyConfig()">
                            </div>
                        </div>
                    </div>

                    <div id="aiPromptPanel" class="ai-prompt-panel">
                        <div class="field-block" style="margin:0;">
                            <label class="field-label" style="margin-bottom:8px;">Custom prompt hệ thống</label>
                            <textarea id="aiCustomPromptInput" placeholder="Dán nội dung prompt hệ thống ở đây..."></textarea>
                        </div>
                        <div style="margin-top:12px; display:flex; gap:10px;">
                            <button class="btn btn-primary" style="height:36px; padding:0 16px; border-radius:8px; font-size:0.9rem;" onclick="saveAICustomPrompt()">💾 Lưu</button>
                            <button class="btn btn-secondary" style="height:36px; padding:0 16px; border-radius:8px; font-size:0.9rem;" onclick="toggleAIPromptPanel(false)">Đóng</button>
                        </div>
                    </div>

                    <div id="aiMessagesList" class="ai-chat-messages"></div>

                    <div class="ai-composer">
                        <textarea id="aiComposerInput" placeholder="Nhập tin nhắn... (Enter để gửi, Shift+Enter để xuống dòng)" onkeydown="onAIComposerKeyDown(event)"></textarea>
                        <div id="aiAttachmentPreview" class="ai-attachment-preview" style="margin-top:0;"></div>
                        <div class="ai-compose-actions">
                            <div class="ai-compose-actions-left">
                                <label class="ai-prompt-btn" style="cursor:pointer; margin:0; font-size:0.85rem;">
                                    📎 Đính kèm
                                    <input id="aiFileInput" type="file" multiple hidden>
                                </label>
                                <button class="ai-prompt-btn" type="button" style="margin:0; font-size:0.85rem;" onclick="clearAIAttachments()">🧹 Xóa</button>
                            </div>
                            <div style="display:flex; gap:10px;">
                                <button class="btn btn-danger" type="button" id="aiStopBtn" style="display:none; border-radius:8px; padding:0 16px; height:40px; font-size:0.9rem;" onclick="stopAIStream()">🛑 Dừng</button>
                                <button class="btn btn-primary" type="button" id="aiSendBtn" style="border-radius:8px; padding:0 24px; height:40px; font-size:0.95rem; font-weight:700;" onclick="sendAIRequest(this)">🚀 Gửi</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
"""

with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
in_ai_css = False
in_ai_html = False

# We will use exact start and end strings to safely replace
css_start = '        .ai-shell {\n'
css_end = '        .installssl-layout {\n'

html_start = '        <div id="tab-ai" class="tab-content"'
html_end = '        </div>\n' # We need to be careful with html_end, better to just use line index.

# Find indices
css_start_idx = -1
css_end_idx = -1
html_start_idx = -1
html_end_idx = -1

for i, line in enumerate(lines):
    if line == css_start and css_start_idx == -1:
        css_start_idx = i
    if line == css_end and css_end_idx == -1:
        css_end_idx = i
    if line.startswith(html_start) and html_start_idx == -1:
        html_start_idx = i
    if line == '    <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>\n':
        html_end_idx = i - 2 # Assuming two </div> before it

if css_start_idx != -1 and css_end_idx != -1 and html_start_idx != -1 and html_end_idx != -1:
    new_lines = lines[:css_start_idx] + [css_replacement] + lines[css_end_idx:html_start_idx] + [html_replacement] + lines[html_end_idx:]
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    print("Replacement successful")
else:
    print(f"Failed to find bounds: css({css_start_idx}, {css_end_idx}), html({html_start_idx}, {html_end_idx})")

