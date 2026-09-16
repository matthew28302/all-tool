import re
with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()
css_match = re.search(r'<style>(.*?)</style>', content, re.DOTALL)
if css_match:
    css = css_match.group(1)
    selectors = set(re.findall(r'^\s*([a-zA-Z0-9_\-\.\#\:\,\s\[\]\=\'\"]+?)\s*\{', css, re.MULTILINE))
    print(f'Found {len(selectors)} selectors.')
else:
    print('No style tag found')
