import re
from pathlib import Path

html = Path("frontend/index.html").read_text(encoding="utf-8")
js_content = {}
full_js = ""
for f in Path("frontend/js").glob("*.js"):
    text = f.read_text(encoding="utf-8")
    js_content[f.name] = text
    full_js += text + "\n"

# 1. Check event handlers
handlers = re.findall(r'on[a-z]+="([^"]+)"', html)
print(f"Total inline event handlers in index.html: {len(handlers)}")

missing_handlers = set()
for h in handlers:
    clean = h.strip()
    for stmt in clean.split(";"):
        stmt = stmt.strip()
        if not stmt:
            continue
        fn_match = re.match(r'^(?:window\.)?([a-zA-Z0-9_$]+)\s*\(', stmt)
        if fn_match:
            fn = fn_match.group(1)
            if fn not in ["alert", "console", "confirm", "prompt"]:
                if not re.search(r'(?:function\s+' + fn + r'|' + fn + r'\s*=\s*(?:function|\()|class\s+' + fn + r')', full_js):
                    missing_handlers.add(fn)

print(f"Missing handler functions: {missing_handlers}")

# 2. Check getElementById calls in JS against IDs in index.html
id_matches = re.findall(r'id="([^"]+)"', html)
html_ids = set(id_matches)

missing_ids = set()
for fname, content in js_content.items():
    js_ids = re.findall(r'getElementById\(["\']([^"\']+)["\']\)', content)
    for jid in js_ids:
        if jid not in html_ids:
            missing_ids.add((fname, jid))

print(f"Total getElementById calls pointing to missing DOM IDs: {len(missing_ids)}")
for fname, jid in sorted(missing_ids):
    print(f"  {fname}: #{jid}")
