import re
import os

# this module is dedicated to figuring out the regex to detect password-like sequences in the files

raw_path = input()
path = raw_path.replace(os.sep, '/')
lines = []
with open(path, encoding='utf-8') as file:
    for line in file:
        if re.search(r'([a-zA-Z]+[0-9]+|[0-9]+[a-zA-Z]+)[+?@^!§$%&]*\S{8,}', line):
            lines.append(line)

print(lines)
