import os
from bs4 import BeautifulSoup
import re

INDEX_PATH = 'templates/index.html'
TABS_DIR = 'templates/tabs'
JS_DIR = 'static/js'

os.makedirs(TABS_DIR, exist_ok=True)
os.makedirs(JS_DIR, exist_ok=True)

with open(INDEX_PATH, 'r', encoding='utf-8') as f:
    html_content = f.read()

soup = BeautifulSoup(html_content, 'html.parser')

# Find the main-content-area
main_content = soup.find(class_='main-content-area')

if not main_content:
    print("Could not find .main-content-area")
    exit(1)

# Extract all .tab-content children
tab_contents = main_content.find_all(class_='tab-content', recursive=False)
if not tab_contents:
    # They might not be direct children. Let's find all inside main-content-area
    tab_contents = main_content.find_all(class_='tab-content')

print(f"Found {len(tab_contents)} tab-content elements in main-content-area.")

# Extract the script tags that have actual content (not src=...)
script_tags = soup.find_all('script')
inline_scripts = []
for script in script_tags:
    if script.string and not script.get('src') and ('function' in script.string or 'document' in script.string):
        inline_scripts.append(script)

# Combine inline scripts into main.js
if inline_scripts:
    with open(os.path.join(JS_DIR, 'main.js'), 'w', encoding='utf-8') as f:
        for script in inline_scripts:
            f.write(script.string)
            f.write('\n\n')
    print(f"Extracted {len(inline_scripts)} inline scripts to static/js/main.js")
    
    # Replace the FIRST inline script we found with the src link, remove the rest
    first = True
    for script in inline_scripts:
        if first:
            new_tag = soup.new_tag('script', src="{{ url_for('static', filename='js/main.js') }}")
            script.replace_with(new_tag)
            first = False
        else:
            script.decompose()

# Process tabs
for tab in tab_contents:
    tab_id = tab.get('id')
    if not tab_id:
        continue
    
    # Write tab to separate file
    filename = tab_id.replace('-', '_') + '.html'
    filepath = os.path.join(TABS_DIR, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(str(tab))
    print(f"Extracted {tab_id} to {filepath}")
    
    # Replace the tab in index.html with jinja include
    # We use a placeholder that won't be HTML-escaped by bs4 if we just replace text.
    # Actually, bs4 will escape NavigableString. We can put a unique comment and then regex replace it.
    placeholder = f"<!-- JINJA_INCLUDE_TAB_{tab_id} -->"
    tab.replace_with(placeholder)

# Write back index.html
new_html = str(soup)

# Restore jinja templates that we turned into comments
for tab in tab_contents:
    tab_id = tab.get('id')
    if tab_id:
        filename = tab_id.replace('-', '_') + '.html'
        placeholder = f"<!-- JINJA_INCLUDE_TAB_{tab_id} -->"
        include_str = "{% include 'tabs/" + filename + "' %}"
        new_html = new_html.replace(placeholder, include_str)

# Some Jinja tags might be escaped by BeautifulSoup, let's fix url_for
new_html = new_html.replace('src="{{ url_for(&#39;static&#39;, filename=&#39;js/main.js&#39;) }}"', 'src="{{ url_for(\'static\', filename=\'js/main.js\') }}"')
new_html = new_html.replace('href="{{ url_for(&#39;static&#39;, filename=&#39;css/style.css&#39;) }}"', 'href="{{ url_for(\'static\', filename=\'css/style.css\') }}"')
new_html = new_html.replace('href="{{ url_for(&#39;static&#39;, filename=&#39;css/theme-premium.css&#39;) }}"', 'href="{{ url_for(\'static\', filename=\'css/theme-premium.css\') }}"')
new_html = new_html.replace('href="{{ url_for(&#39;static&#39;, filename=&#39;favicon.ico&#39;) }}"', 'href="{{ url_for(\'static\', filename=\'favicon.ico\') }}"')

with open(INDEX_PATH, 'w', encoding='utf-8') as f:
    f.write(new_html)

print("Updated templates/index.html")
