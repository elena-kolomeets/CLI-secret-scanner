## CLI-secret-scanner
Command-line tool for scanning project directory for secrets that should not be shared

**Description**

The program scans all files in all subdirectories of the current or specified directory for secrets (password, secret key etc.) 
that have not been hidden (e.g. added to .env) locally.

By default files added to .gitignore are NOT scanned but you can change it.

After scanning a summary of the results is written in the terminal and in "secret_scanner_results.txt" file.
In case secrets are found the detailed report is given in "secret_scanner_detailed_report.txt" file.
Both files are generated in the scanned dir and added to .gitignore (created if does not exist).


**How to use**  

Run .exe or .py file in your terminal. Without arguments the current directory will be scanned and files added to .gitignore will be ignored.

Optional arguments:

```
  -p [path] / --path [path] : provide the absolute or relative path to the directory that needs to be scanned
  -a / --all                : use this flag to scan all files, including the files added to .gitignore
  -h / --help               : show this help message and exit
```

**Limitations**

1. The tool scans for a combination of words like "password", "key", "database-url" and their variations with ":", "=", "is" with or without whitespace. There is currently no check for false positives. 
2. The tool scans directories containing not more than 1000 files. (Make sure virtualenv/venv dir is not inside.) In case your dir is too big the tool will let you know.

**Thank you**

Feel free to use the tool and reach out with improvement suggestions.