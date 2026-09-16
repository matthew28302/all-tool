import re
with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'r', encoding='utf-8') as f:
    c = f.read()
# Extract structural elements (IDs, classes of main containers)
print("BODY STRUCTURE:")
for line in c.split('\n')[2850:2890]: # just a peek at the start of body
    print(line)
