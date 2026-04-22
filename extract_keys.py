import re
import os
import json

keys = {}
pattern = re.compile(r"t\(request,\s*'([^']+)',\s*default='([^']+)'\)")
for root, _, files in os.walk('templates'):
    for file in files:
        if file.endswith('.html'):
            with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                content = f.read()
                matches = pattern.findall(content)
                for k, v in matches:
                    keys[k] = v

print(json.dumps(keys, indent=2))
