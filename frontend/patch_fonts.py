"""
Add Google Fonts preconnect links to all HTML files for Lora + Inter.
Also ensure data-theme defaults to "light" (matching the editorial design).
"""
import os, re, sys
sys.stdout.reconfigure(encoding='utf-8')

FONT_LINK = (
    '  <link rel="preconnect" href="https://fonts.googleapis.com">\n'
    '  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n'
    '  <link href="https://fonts.googleapis.com/css2?family=Lora:ital,wght@0,400;0,600;0,700;1,400&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">\n'
)

html_files = [
    'frontend/index.html',
    'frontend/verify.html',
    'frontend/learn.html',
    'frontend/help.html',
    'frontend/report-card.html',
]

for fpath in html_files:
    with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Set data-theme to "light" as default
    content = re.sub(r'<html([^>]*?)data-theme="dark"', r'<html\1data-theme="light"', content)

    # 2. Inject Google Fonts after the stylesheet link if not already present
    if 'fonts.googleapis.com/css2?family=Lora' not in content:
        content = content.replace(
            '  <link rel="stylesheet" href="/css/style.css">',
            '  <link rel="stylesheet" href="/css/style.css">\n' + FONT_LINK.rstrip('\n')
        )

    with open(fpath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f'Updated: {fpath}')

print('All HTML files updated.')
