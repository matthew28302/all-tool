import re

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Fix the extra </div>
content = content.replace('''                            </div>
                        </div>
                        </div>

                        <div class="record-types" id="recordTypes">''', '''                            </div>
                        </div>

                        <div class="record-types" id="recordTypes">''')

# 2. Fix the layout of dns-stats-card. The user said it is squashed.
# In the original CSS, dns-hero might have been a grid.
# I will make sure dns-hero is a clean grid.
css_fix = '''
        .dns-hero {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 24px;
        }
        @media (max-width: 992px) {
            .dns-hero { grid-template-columns: 1fr; }
        }
        .dns-stats-card {
            display: flex;
            flex-direction: column;
            justify-content: space-around;
            padding: 24px;
        }
        .dns-stat-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            margin-bottom: 8px;
            background: #f8fafc;
        }
        .dns-stat-row:last-child { margin-bottom: 0; }
        
        .dns-search-card { padding: 24px; }
'''
content = content.replace('/* --- INNER TAB PASTEL STYLES --- */', '/* --- INNER TAB PASTEL STYLES --- */\n' + css_fix)

with open('c:/Users/NVX/Downloads/all-tool/templates/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print('Fixed extra div and dns-hero grid.')
