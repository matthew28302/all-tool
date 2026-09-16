import re

file_path = r'c:\Users\NVX\Downloads\all-tool\templates\index.html'

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the .tab-btn block in CSS using regex
# We want to match from `.tab-btn {` all the way down to `.tab-btn .icon { ... }`
# We know it starts at `.tab-btn {` and ends before `.main-content-area`
match = re.search(r'\.tab-btn\s*\{.*?(?=\.main-content-area)', content, re.DOTALL)
if match:
    old_css = match.group(0)
    new_css = """        .nav-group-header {
            font-size: 0.72rem;
            font-weight: 800;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            padding: 16px 12px 6px;
            margin-top: 4px;
        }
        .nav-group-header:first-child { margin-top: 0; padding-top: 8px; }
        .nav-divider {
            height: 1px;
            background: #f1f5f9;
            margin: 12px 16px;
        }

        .tab-btn {
            flex: 0 0 auto;
            padding: 12px 16px;
            border: 1px solid transparent;
            background: transparent;
            color: #64748b;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            align-items: center;
            justify-content: flex-start;
            gap: 12px;
            border-radius: 12px;
            white-space: nowrap;
            margin: 0 8px;
        }
        .tab-btn:hover { 
            background: #f8fafc; 
            color: #0f172a; 
            border-color: #e2e8f0;
            transform: translateX(4px);
        }
        .tab-btn.active {
            background: #f0f9ff;
            color: #0284c7;
            border-color: #bae6fd;
            box-shadow: 0 2px 6px rgba(14, 165, 233, 0.1);
        }
        .tab-btn.ai-tab-btn:hover {
            border-color: #fce7f3;
            background: #fdf2f8;
            color: #be185d;
        }
        .tab-btn.ai-tab-btn.active {
            background: #fdf4ff;
            color: #c026d3;
            border-color: #f5d0fe;
            box-shadow: 0 2px 6px rgba(192, 38, 211, 0.1);
        }
        .tab-btn .icon { font-size: 1.2rem; }
        
"""
    content = content.replace(old_css, new_css)
else:
    print("Could not find .tab-btn in CSS")

# Write it back
with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("CSS Fixed")
