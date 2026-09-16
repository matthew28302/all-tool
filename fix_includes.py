import re

with open('templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix backslashes and dashes
content = content.replace("\\'", "'")
# tab-dns.html -> tab_dns.html
content = re.sub(r"tabs/tab-(.*?)\.html", r"tabs/tab_\1.html", content)

with open('templates/index.html', 'w', encoding='utf-8') as f:
    f.write(content)
print('Fixed includes!')
