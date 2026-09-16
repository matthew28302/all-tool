import re
with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Let's add a responsive wrapper for tables if they are used, or ensure .server-row and .record-col-header have overflow handles
# The old CSS has hardcoded grid-template-columns: 130px 120px 1fr for .server-row
# We should override it in media queries to flex-direction column on mobile
mobile_css = '''
        /* Responsive overrides for DNS tables on mobile */
        @media (max-width: 640px) {
            .record-col-header {
                display: none; /* Hide header on mobile */
            }
            .server-row {
                display: flex;
                flex-direction: column;
                align-items: flex-start;
                gap: 8px;
                padding: 16px;
            }
            .server-name { font-size: 1.05rem; }
            .server-ip { font-size: 0.9rem; }
        }
'''

content = content.replace('/* Mobile fixes */', mobile_css + '\n        /* Mobile fixes */')

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print('Successfully applied mobile responsiveness overrides.')
