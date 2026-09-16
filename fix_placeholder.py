import re
with open('templates/tabs/tab_ai.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the bad placeholder
content = content.replace('placeholder="<span class="icon" data-lucide="search"></span> Tìm kiếm Model..."', 'placeholder="Tìm kiếm Model..."')

with open('templates/tabs/tab_ai.html', 'w', encoding='utf-8') as f:
    f.write(content)
print('Fixed placeholder!')
