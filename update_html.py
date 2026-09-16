import re
with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Refactor the DNS Search Row to an input-group
dns_search_pattern = re.compile(
    r'<div class="dns-search-row">.*?<input type="text" class="dns-input" id="domainInput".*?>.*?<div class="dns-actions">.*?<button class="btn btn-primary" onclick="checkDNS\(\)">🔍 Kiểm tra</button>.*?</div>',
    re.DOTALL
)

def dns_search_replacer(match):
    # We will build a much cleaner input group
    return '''<div class="dns-search-row">
                            <div class="input-group" style="flex: 1;">
                                <input type="text" class="dns-input" id="domainInput"
                                       placeholder="Nhập tên miền (vd: google.com)"
                                       onkeypress="if(event.key==='Enter')checkDNS()">
                                <button class="btn btn-primary" onclick="checkDNS()">🔍 Kiểm tra</button>
                            </div>
                            <div style="display:flex;gap:8px;align-items:center;">
                                <div class="dns-view-switch" role="group" aria-label="DNS mode" style="margin-right:6px;">
                                    <button type="button" id="dnsModeDetailBtnInline" class="dns-view-btn active" onclick="setDnsMode('detail')">Detail</button>
                                    <button type="button" id="dnsModeBasicBtnInline" class="dns-view-btn" onclick="setDnsMode('basic')">Basic</button>
                                </div>
                                <div class="dns-actions">
                                    <button class="btn btn-secondary" onclick="clearCache()" style="padding: 14px 20px;">🗑️ Clear</button>
                                </div>
                            </div>
                        </div>'''

new_content = dns_search_pattern.sub(dns_search_replacer, content)

# Check if the replacement occurred
if content == new_content:
    print('Regex failed to match DNS Search Row')
else:
    with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'w', encoding='utf-8') as f:
        f.write(new_content)
    print('Successfully applied input-group HTML to DNS.')
