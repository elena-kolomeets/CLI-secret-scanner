## CLI-secret-scanner
Command-line tool for scanning project directory for secrets that should not be shared

### secret_scanner.py or secret_scanner.exe:
*using my own secret scanning algorithm*
### gg_secret_scanner.py or gg_secret_scanner.exe:
*using [GitGuardian API](https://github.com/GitGuardian/py-gitguardian) secret scanning algorithm*

**Description**

Both programs scan all files in all subdirectories of the current or specified directory for secrets (password, secret key etc.) 
that have not been hidden (e.g. added to .env) locally. 

By default files added to .gitignore are NOT scanned but you can change it.

After scanning a summary of the results is written in the terminal and in "secret_scanner_results.txt" file.
In case secrets are found the detailed report is given in the same file which is generated in the scanned folder
and added to .gitignore (created if does not exist).


**How to use**  

To use both programs run .exe or .py file **in your terminal**. 
Without arguments the current directory will be scanned, 
and files added to .gitignore will be ignored. The same happens if you just execute .exe files.

Optional arguments:

```
  -p [path] / --path [path] : provide the absolute or relative path to the directory that needs to be scanned
  -a / --all                : use this flag to scan all files, including the files added to .gitignore
  -h / --help               : show this help message and exit
```

**Limitations**

1. The **secret_scanner** scans file names and texts for a combination of words like *"password", "key", "token", "database-url"* 
   and their variations with *":", "=", "_", "is"*, with or without whitespace,
   and a regular expression for password/key-like strings. It does not find standalone passwords/keys in the text. 
2. The **gg_secret_scanner** does not find short simple passwords/keys even if they have the word "password" etc. in front of them. 
   Some standalone keys can be missed as well.
3. Both tools scans directories containing not more than *3000 files*. (Make sure virtualenv/venv dir is not inside.) 
   In case your dir is too big the tool will let you know.

The best approach is to use both tools and compare results.

***

Feel free to use the tools and reach out with improvement suggestions.
