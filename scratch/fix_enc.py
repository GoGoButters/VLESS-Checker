import sys
import codecs

# read utf-16le and write utf-8
with codecs.open('scratch/main_old.py', 'r', 'utf-16le') as f:
    content = f.read()
with codecs.open('scratch/main_old.py', 'w', 'utf-8') as f:
    f.write(content)
