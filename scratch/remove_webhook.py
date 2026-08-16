import sys
import codecs

def remove_webhook_output(file_path):
    with codecs.open(file_path, 'r', 'utf-8') as f:
        lines = f.readlines()
        
    start = -1
    end = -1
    for i, line in enumerate(lines):
        if '@app.get("/{secret_path:path}")' in line:
            start = i
        if start != -1 and '# ---------------------------------------------------------------------------' in line and i + 1 < len(lines) and 'Run with uvicorn' in lines[i+1]:
            end = i
            break
            
    if start != -1 and end != -1:
        del lines[start:end]
        with codecs.open(file_path, 'w', 'utf-8') as f:
            f.writelines(lines)
        print(f"Removed lines {start+1} to {end}")
    else:
        print("Could not find block to remove.")

remove_webhook_output('main.py')
