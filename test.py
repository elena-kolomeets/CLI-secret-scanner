import re
import os

raw_path = input()
path = raw_path.replace(os.sep, '/')
lines = []
with open(path, encoding='utf-8') as file:
    for line in file:
        if re.search(r'([a-zA-Z]+[0-9]+|[0-9]+[a-zA-Z]+)[+?@^!§$%&]*\S{8,}', line):
            lines.append(line)

print(lines)
