import re

with open('templates/tabs/tab_ai.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Replace inline styles and add 'ai-premium-select' class to the 2 selects
html = re.sub(
    r'class="dns-input" id="aiProviderSelect" onchange="onAIProviderChange\(\)" style="[^"]*"',
    r'class="dns-input ai-premium-select" id="aiProviderSelect" onchange="onAIProviderChange()"',
    html
)
html = re.sub(
    r'class="dns-input" id="aiModelSelect" onchange="onAIModelSelectChange\(\)" style="[^"]*"',
    r'class="dns-input ai-premium-select" id="aiModelSelect" onchange="onAIModelSelectChange()"',
    html
)

with open('templates/tabs/tab_ai.html', 'w', encoding='utf-8') as f:
    f.write(html)

print("Updated HTML")
