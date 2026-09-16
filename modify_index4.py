import sys

file_path = r'c:\Users\NVX\Downloads\all-tool\templates\index.html'

with open('modify_index3.py', 'r', encoding='utf-8') as f:
    exec(f.read())

with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

css_start_idx = -1
css_end_idx = -1
html_start_idx = -1
html_end_idx = -1

for i, line in enumerate(lines):
    if line == '        .ai-shell {\n' and css_start_idx == -1:
        css_start_idx = i
    if line == '        .installssl-layout {\n' and css_end_idx == -1:
        css_end_idx = i
    if line.strip().startswith('<div id="tab-ai" class="tab-content"') and html_start_idx == -1:
        html_start_idx = i
    if line == '    <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>\n':
        html_end_idx = i - 2

if css_start_idx != -1 and css_end_idx != -1 and html_start_idx != -1 and html_end_idx != -1:
    new_lines = lines[:css_start_idx] + [css_replacement] + lines[css_end_idx:html_start_idx] + [html_replacement] + lines[html_end_idx:]
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    print("Replacement successful")
else:
    print(f"Failed to find bounds: css({css_start_idx}, {css_end_idx}), html({html_start_idx}, {html_end_idx})")
