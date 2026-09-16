import sys

file_path = r'c:\Users\NVX\Downloads\all-tool\templates\index.html'

css_replacement = """        .ai-shell {
            display: grid;
            grid-template-columns: 320px minmax(0, 1fr);
            gap: 24px;
            align-items: start;
            box-sizing: border-box;
        }
        @media (max-width: 992px) {
            .ai-shell {
                grid-template-columns: 1fr;
            }
        }
        .ai-sidebar, .ai-chat-pane {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 10px 30px rgba(15, 23, 42, 0.04);
            box-sizing: border-box;
            display: flex;
            flex-direction: column;
        }
        .ai-sidebar {
            max-height: calc(100vh - 40px);
            position: sticky;
            top: 20px;
        }
        .ai-sidebar-header, .ai-chat-header, .ai-toolbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .ai-history-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
            overflow-y: auto;
            padding-right: 6px;
            flex: 1;
        }
        .ai-history-list::-webkit-scrollbar {
            width: 6px;
        }
        .ai-history-list::-webkit-scrollbar-thumb {
            background-color: #cbd5e1;
            border-radius: 10px;
        }
        .ai-history-item {
            border: 1px solid transparent;
            border-radius: 12px;
            padding: 12px 14px;
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
            box-shadow: 0 4px 12px rgba(14, 165, 233, 0.1);
        }
        .ai-history-title {
            font-weight: 700;
            color: #0f172a;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-size: 0.95rem;
        }
        .ai-history-meta {
            font-size: 0.8rem;
            color: #64748b;
            margin-top: 6px;
        }
        .ai-prompt-btn, .ai-icon-btn {
            border: 1px solid #cbd5e1;
            background: #ffffff;
            color: #334155;
            border-radius: 999px;
            padding: 8px 16px;
            font-size: 0.9rem;
            font-weight: 700;
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
            box-shadow: 0 4px 12px rgba(14, 165, 233, 0.2);
        }
        .ai-prompt-panel {
            display: none;
            margin-top: 16px;
            padding: 20px;
            border: 1px solid #e2e8f0;
            border-radius: 16px;
            background: #f8fafc;
            box-sizing: border-box;
        }
        .ai-prompt-panel.show { display: block; }
        .ai-prompt-panel textarea {
            width: 100%;
            min-height: 120px;
            border: 1px solid #cbd5e1;
            border-radius: 12px;
            padding: 14px;
            font: inherit;
            resize: vertical;
            box-sizing: border-box;
            background: #ffffff;
        }
        .ai-chat-messages {
            display: flex;
            flex-direction: column;
            gap: 16px;
            min-height: 450px;
            max-height: 65vh;
            overflow-y: auto;
            padding-right: 12px;
            background: #fafaf9;
            border-radius: 16px;
            padding: 20px;
            border: 1px inset #f5f5f4;
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
            border-radius: 18px;
            padding: 14px 20px;
            max-width: 85%;
            white-space: pre-wrap;
            word-break: break-word;
            line-height: 1.6;
            box-shadow: 0 4px 10px rgba(0,0,0,0.02);
            font-size: 0.98rem;
        }
        .ai-chat-bubble.user {
            background: linear-gradient(135deg, #0ea5e9, #2563eb);
            color: #fff;
            margin-left: auto;
            border-bottom-right-radius: 4px;
        }
        .ai-chat-bubble.assistant {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            color: #1e293b;
            margin-right: auto;
            border-bottom-left-radius: 4px;
        }
        .ai-chat-bubble .meta {
            font-size: 0.78rem;
            opacity: 0.8;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .ai-attachment-preview {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-top: 12px;
        }
        .ai-attachment-item {
            border: 1px solid #cbd5e1;
            border-radius: 12px;
            padding: 6px;
            background: #fff;
            position: relative;
        }
        .ai-attachment-item img {
            max-width: 140px;
            max-height: 140px;
            border-radius: 8px;
            display: block;
            object-fit: cover;
        }
        .ai-composer {
            margin-top: 20px;
            border: 1px solid #e2e8f0;
            border-radius: 20px;
            padding: 16px;
            background: #ffffff;
            box-shadow: 0 8px 24px rgba(0,0,0,0.04);
            display: flex;
            flex-direction: column;
            gap: 12px;
            box-sizing: border-box;
            transition: all 0.2s ease;
        }
        .ai-composer:focus-within {
            border-color: #0ea5e9;
            box-shadow: 0 8px 24px rgba(14, 165, 233, 0.1);
        }
        .ai-composer textarea {
            width: 100%;
            min-height: 60px;
            max-height: 200px;
            border: none;
            padding: 8px;
            resize: vertical;
            font: inherit;
            box-sizing: border-box;
            background: transparent;
            outline: none;
            font-size: 0.98rem;
        }
        .ai-composer textarea::placeholder {
            color: #94a3b8;
        }
        .ai-compose-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            align-items: center;
            justify-content: space-between;
            border-top: 1px solid #f1f5f9;
            padding-top: 16px;
        }
        .ai-compose-actions-left {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }
        .ai-file-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border-radius: 999px;
            padding: 8px 14px;
            background: #e0f2fe;
            color: #0369a1;
            font-size: 0.85rem;
            font-weight: 700;
        }
        .ai-empty {
            color: #64748b;
            padding: 40px 20px;
            border: 2px dashed #cbd5e1;
            border-radius: 16px;
            background: #f8fafc;
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 12px;
        }
        .ai-model-chip {
            height: 36px;
            padding: 0 16px;
            border: 1px solid #cbd5e1;
            background: #ffffff;
            color: #475569;
            border-radius: 999px;
            font-size: 0.85rem;
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
            box-shadow: 0 4px 12px rgba(14, 165, 233, 0.2);
        }
        .ai-filter-tab {
            height: 36px;
            padding: 0 16px;
            border: 1px solid #cbd5e1;
            background: #ffffff;
            color: #475569;
            border-radius: 999px;
            font-size: 0.85rem;
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
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.2);
        }
        .ai-badge-active {
            display: inline-flex;
            align-items: center;
            background: #dbeafe;
            color: #1e40af;
            border: 1px solid #bfdbfe;
            padding: 6px 14px;
            border-radius: 999px;
            font-size: 0.85rem;
            font-weight: 700;
            max-width: 250px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .btn-danger {
            height: 42px;
            background: #ef4444;
            color: #ffffff;
            border: 1px solid #dc2626;
            font-weight: 700;
            padding: 0 20px;
            border-radius: 12px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
        }
        .btn-danger:hover {
            background: #dc2626;
            box-shadow: 0 4px 12px rgba(220, 38, 38, 0.2);
        }
        .ai-provider-bar {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 4px 24px rgba(15, 23, 42, 0.04);
            display: flex;
            flex-direction: column;
            gap: 20px;
            box-sizing: border-box;
        }
        .ai-provider-row {
            display: grid;
            grid-template-columns: 240px minmax(0, 1fr) auto;
            gap: 20px;
            align-items: end;
            width: 100%;
            box-sizing: border-box;
        }
        .ai-filter-row {
            display: grid;
            grid-template-columns: 280px minmax(0, 1fr);
            gap: 20px;
            align-items: center;
            border-top: 1px solid #f1f5f9;
            padding-top: 20px;
            width: 100%;
            box-sizing: border-box;
        }
        @media (max-width: 992px) {
            .ai-provider-row {
                grid-template-columns: 1fr;
            }
            .ai-filter-row {
                grid-template-columns: 1fr;
                gap: 16px;
            }
        }
        .ai-render-image {
            margin-top: 12px;
            max-width: 100%;
            border-radius: 12px;
            border: 1px solid #e2e8f0;
            box-shadow: 0 4px 16px rgba(0,0,0,0.06);
        }
"""

html_replacement = """        <div id="tab-ai" class="tab-content" role="tabpanel" aria-labelledby="tabbtn-ai" hidden>
            <div class="ai-shell">
                <aside class="ai-sidebar" id="aiSidebar">
                    <div class="ai-sidebar-header">
                        <div>
                            <div class="dns-panel-title">💬 Chat History</div>
                        </div>
                        <button class="btn btn-secondary btn-compact" onclick="createNewAIChat()">+ mới</button>
                    </div>
                    <div id="aiHistoryList" class="ai-history-list"></div>
                </aside>

                <div class="ai-chat-pane">
                    <div class="ai-chat-header">
                        <div>
                            <div class="dns-panel-title" style="display:flex; align-items:center; gap:12px;">
                                🤖 AI Chat (Streaming)
                                <span id="aiActiveModelBadge" class="ai-badge-active" title="Model đang sử dụng">meta/llama-3.3-70b-instruct</span>
                            </div>
                            <div class="dns-panel-subtitle">Khảo sát tốc độ song song, ngắt kết nối trực tiếp & phản hồi thời gian thực.</div>
                        </div>
                        <div class="ai-toolbar">
                            <button class="btn btn-secondary btn-compact" type="button" onclick="deleteActiveAIChat()" title="Xoá đoạn chat hiện tại">🗑️ Xóa</button>
                            <button class="ai-prompt-btn" id="aiPromptToggle" type="button" onclick="toggleAIPromptPanel()">⚙️ Settings</button>
                        </div>
                    </div>

                    <!-- AI Config & Model Control Center -->
                    <div class="ai-provider-bar">
                        <!-- Row 1: Provider, Model Select, Actions -->
                        <div class="ai-provider-row">
                            <div style="display:flex; flex-direction:column; gap:8px;">
                                <label style="font-size:0.88rem; font-weight:700; color:#334155;">Nhà cung cấp:</label>
                                <select id="aiProviderSelect" class="dns-input" style="height:44px; padding:0 16px; font-size:0.95rem; border-radius:12px;" onchange="onAIProviderChange()">
                                    <option value="nvidia" selected>⚡ NVIDIA NIM</option>
                                    <option value="agnes">🤖 Agnes AI</option>
                                    <option value="custom">⚙️ Custom API</option>
                                </select>
                            </div>

                            <div style="display:flex; flex-direction:column; gap:8px; min-width:0;">
                                <label style="font-size:0.88rem; font-weight:700; color:#334155;">Model AI (<span id="aiModelCount">Đang tải...</span>):</label>
                                <select id="aiModelSelect" class="dns-input" style="height:44px; padding:0 16px; font-size:0.95rem; border-radius:12px; text-overflow:ellipsis;" onchange="onAIModelSelectChange()">
                                    <option value="meta/llama-3.3-70b-instruct">meta/llama-3.3-70b-instruct</option>
                                </select>
                            </div>

                            <div style="display:flex; gap:12px; align-items:flex-end;">
                                <button type="button" class="btn btn-primary" style="height:44px; padding:0 24px; background:#4f46e5; border:none; border-radius:12px; font-weight:700; font-size:0.95rem; display:flex; align-items:center; gap:8px;" id="aiTestSpeedBtn" onclick="testAllModelsSpeed()">
                                    <span>⚡</span> Test Connection (Song Song)
                                </button>
                                <button type="button" class="btn btn-secondary" style="height:44px; padding:0 18px; border-radius:12px; font-weight:600; display:flex; align-items:center; gap:8px;" onclick="loadAIModels(true)">
                                    <span>🔄</span> Reload
                                </button>
                            </div>
                        </div>

                        <!-- Row 2: Search Input & Speed Filters -->
                        <div class="ai-filter-row">
                            <div>
                                <input type="text" id="aiModelSearchInput" class="dns-input" style="height:42px; padding:0 16px; font-size:0.95rem; border-radius:12px; width:100%; box-sizing:border-box;" placeholder="🔍 Tìm kiếm Model (llama, deepseek...)" oninput="filterAIModels()">
                            </div>

                            <div style="display:flex; flex-wrap:wrap; gap:10px; align-items:center; justify-content:flex-end;">
                                <span style="font-size:0.88rem; font-weight:700; color:#64748b; margin-right:8px;">Phân loại:</span>
                                <button type="button" class="ai-filter-tab active" data-speed="all" onclick="setAISpeedFilter('all', this)">Tất cả</button>
                                <button type="button" class="ai-filter-tab" data-speed="fast" onclick="setAISpeedFilter('fast', this)">🚀 Nhanh (<1.5s)</button>
                                <button type="button" class="ai-filter-tab" data-speed="medium" onclick="setAISpeedFilter('medium', this)">⚡ T.Bình (1.5-3.2s)</button>
                                <button type="button" class="ai-filter-tab" data-speed="slow" onclick="setAISpeedFilter('slow', this)">🐢 Chậm (>3.2s)</button>
                                <button type="button" class="ai-filter-tab" data-speed="working" onclick="setAISpeedFilter('working', this)">🛡️ Chỉ model hoạt động</button>
                            </div>
                        </div>

                        <!-- Row 3: Presets -->
                        <div style="display:flex; flex-wrap:wrap; gap:12px; align-items:center; width:100%; box-sizing:border-box;">
                            <span style="font-size:0.88rem; font-weight:700; color:#64748b; margin-right:8px;">Gợi ý nổi bật:</span>
                            <button type="button" class="ai-model-chip" onclick="selectAIModel('meta/llama-3.3-70b-instruct')">⚡ Llama 3.3 70B</button>
                            <button type="button" class="ai-model-chip" onclick="selectAIModel('deepseek-ai/deepseek-r1')">🔥 DeepSeek R1</button>
                            <button type="button" class="ai-model-chip" onclick="selectAIModel('nvidia/llama-3.1-nemotron-70b-instruct')">🤖 Nemotron 70B</button>
                            <button type="button" class="ai-model-chip" onclick="selectAIModel('mistralai/mistral-large-2-instruct')">💨 Mistral Large 2</button>
                            <button type="button" class="ai-model-chip" onclick="selectAIModel('qwen/qwen2.5-72b-instruct')">🌟 Qwen 2.5 72B</button>
                        </div>

                        <div id="aiTestStatusProgress" style="display:none; margin-top:16px; background:#e0e7ff; color:#3730a3; padding:16px 20px; border-radius:16px; font-size:0.95rem; font-weight:600; box-shadow:0 4px 12px rgba(55,48,163,0.1);">
                            ⚡ Đang kiểm thử kết nối song song tới tất cả model... Vui lòng đợi trong giây lát.
                        </div>

                        <div id="aiCustomKeyBlock" style="margin-top:16px; display:none;">
                            <div style="display:flex; gap:16px; flex-wrap:wrap;">
                                <input type="text" id="aiApiKeyInput" class="dns-input" style="flex:1; min-width:250px; padding:12px 16px; font-size:0.95rem; border-radius:12px;" placeholder="API Key (VD: nvapi-... hoặc sk-...)" onchange="saveAIKeyConfig()">
                                <input type="text" id="aiApiBaseInput" class="dns-input" style="flex:1; min-width:250px; padding:12px 16px; font-size:0.95rem; border-radius:12px;" placeholder="API Base URL (VD: https://integrate.api.nvidia.com/v1)" onchange="saveAIKeyConfig()">
                            </div>
                        </div>
                    </div>

                    <div id="aiPromptPanel" class="ai-prompt-panel">
                        <div class="field-block">
                            <label class="field-label">Custom prompt hệ thống</label>
                            <textarea id="aiCustomPromptInput" placeholder="Dán nội dung prompt hệ thống ở đây..."></textarea>
                        </div>
                        <div class="ai-actions" style="margin-top:16px; display:flex; gap:12px;">
                            <button class="btn btn-primary" onclick="saveAICustomPrompt()">💾 Lưu</button>
                            <button class="btn btn-secondary" onclick="toggleAIPromptPanel(false)">Đóng</button>
                        </div>
                    </div>

                    <div id="aiMessagesList" class="ai-chat-messages"></div>

                    <div class="ai-composer">
                        <textarea id="aiComposerInput" placeholder="Nhập prompt hoặc dán ảnh trực tiếp vào đây... (Bấm Enter để gửi, Shift+Enter để xuống dòng)" onkeydown="onAIComposerKeyDown(event)"></textarea>
                        <div id="aiAttachmentPreview" class="ai-attachment-preview"></div>
                        <div class="ai-compose-actions">
                            <div class="ai-compose-actions-left">
                                <label class="btn btn-secondary" style="cursor:pointer; border-radius:999px; padding:8px 16px; display:flex; align-items:center; gap:6px;">
                                    📎 Đính kèm
                                    <input id="aiFileInput" type="file" multiple hidden>
                                </label>
                                <button class="btn btn-secondary" type="button" style="border-radius:999px; padding:8px 16px; display:flex; align-items:center; gap:6px;" onclick="clearAIAttachments()">🧹 Xóa</button>
                            </div>
                            <div style="display:flex; gap:12px;">
                                <button class="btn btn-danger" type="button" id="aiStopBtn" style="display:none; border-radius:12px; padding:0 24px; font-weight:700;" onclick="stopAIStream()">🛑 Dừng Stream</button>
                                <button class="btn btn-primary" type="button" id="aiSendBtn" style="border-radius:12px; padding:0 32px; font-weight:700; font-size:0.95rem;" onclick="sendAIRequest(this)">🚀 Gửi</button>
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

for line in lines:
    if line.strip() == '.ai-shell {':
        in_ai_css = True
        new_lines.append(css_replacement)
        continue
    if in_ai_css:
        if line.strip() == '.installssl-layout {':
            in_ai_css = False
            new_lines.append(line)
        continue
        
    if line.strip() == '<div id="tab-ai" class="tab-content" role="tabpanel" aria-labelledby="tabbtn-ai" hidden>':
        in_ai_html = True
        new_lines.append(html_replacement)
        continue
        
    if in_ai_html:
        if line.strip() == '<script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>':
            # Note: the replacement string ends exactly after the </div> that closes tab-ai's parent. Wait! 
            # I need to verify that I replace the correct number of lines.
            pass

# Using exact line numbers instead to be absolutely safe
with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()
# Based on earlier view_file output:
# CSS .ai-shell is line 66, up to line 337 (.ai-render-image)
# HTML <div id="tab-ai" is line 3587, up to line 3710 (</div>)

new_lines = lines[:65] + [css_replacement] + lines[337:3586] + [html_replacement] + lines[3710:]

with open(file_path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("Replacement successful")
