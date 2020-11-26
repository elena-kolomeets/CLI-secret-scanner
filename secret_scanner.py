import glob
import os
import sys
import json
import argparse

parser = argparse.ArgumentParser(
    prog='Secret Scanner',
    usage='This tool is used for scanning project directory for secrets that should not be shared.'
          'Run .exe or .py file in your terminal. Use -h/--help flag to get more information.',
    description='The program scans the files of the current or specified (with -p/--path) directory for secrets '
                '(password, secret key etc.) that have not been hidden (e.g. added to .env). '
                'By default files added to .gitignore are NOT scanned. You can change it by using the -a/--all flag. '
                'After scanning a summary of the results is given in "secret_scanner_results.txt" file '
                'and in case secrets are found the detailed report is given in "secret_scanner_detailed_report.txt" file'
                '(both generated in the scanned dir and added to .gitignore) '
                'and in the terminal.',
    epilog='The author is Elena Kolomeets (GitHub elena-kolomeets).',
)
parser.add_argument(
    '-p', '--path',
    type=str,
    default='.',
    required=False,
    help='Provide the absolute or relative path to the directory that needs to be scanned for secrets. '
         'By default the current directory is used.',
    metavar='[path]',
)
parser.add_argument(
    '-a', '--all',
    required=False,
    action='store_true',
    help='Use this flag to scan all files, including the files added to .gitignore (not scanned by default)',
)

args = parser.parse_args()


def ignore(user_path):
    """
    Function that checks if dir contains .gitignore
    and returns a list of all ignored files from all subdirs.
    :param user_path: the path given by the user with -p/--path parameter
    :return: a list of files to ignore while scanning
    """
    gitignore, ignore_list = [], []
    if os.path.exists(user_path + '/.gitignore'):
        with open(user_path + '/.gitignore') as g:
            for line in g:
                if line != '' and line != '\n':
                    if '\n' in line:
                        line = line[:-1]
                    if line[-1] == '/':
                        line = line + '*'
                    if line[:2] == '**':
                        line = line[2:]
                    gitignore.append(line)
        for i in gitignore:
            i = user_path + '/**/' + i + '*'
            for j in glob.glob(i, recursive=True):
                ignore_list.append(os.path.relpath(j, start=user_path))
    return ignore_list


def generate_words():
    """
    Generate a list of words to search for while scanning for secrets.
    :return: the list of secret words and expressions
    """
    words_case, secret_words = [], []
    for word in ['password', 'pass', 'key', 'credential', 'database_url', 'database-url', 'db_url', 'db-url']:
        words_case.extend((word, word.upper(), word.capitalize()))
    for word in words_case:
        secret_words.extend((word + ':', word + ' :', word + '=', word + ' =', word + ' is'))
    return secret_words


def scan(userpath, scan_ignore, secret_words):
    """
    Scanning the folder for secrets: scanning each folder and subfolder
    and adding file names and their lines with secrets to list of dictionaries
    :param userpath:
    :param scan_ignore: flag
    :param secret_words: list of secret words to scan for
    :return: file_list: list of dictionaries with the results
    """

    file_list = []
    for name in glob.glob(userpath, recursive=True):
        if os.path.isdir(name) or os.path.relpath(name, start=userpath)[6:] in scan_ignore \
                or os.path.basename(name) == 'secret_scanner_results.txt' \
                or os.path.basename(name) == 'secret_scanner_detailed_report.txt':
            continue
        try:
            with open(name, mode='r', encoding='utf-8') as f:
                for file_line in f:
                    for secret_word in secret_words:
                        if secret_word in file_line:
                            file_list.append({'file_name': os.path.relpath(name, start=userpath)[6:],
                                              'file_line': file_line})
        except Exception:
            # continue scanning if some files could not be open (like images or executables)
            continue
    return file_list


def write_output(user_path, file_list, output):
    # writing the scan output to the terminal and 'secret_scanner_results.txt'
    print(output, file=sys.stdout)
    with open(user_path + '/' + 'secret_scanner_results.txt', mode='w') as f:
        f.write(output)
    # creating the file with detailed report of the scan results
    if file_list:
        with open(user_path + '/' + 'secret_scanner_detailed_report.txt', mode='w') as f1:
            for results in file_list:
                json.dump(results, f1, indent=2)
    # adding result and report files to .gitignore
    with open(user_path + '/.gitignore', mode='a+') as g:
        g.seek(0)
        if '\nsecret_scanner_results.txt' not in g.read():
            g.write('\nsecret_scanner_results.txt')
        g.seek(0)
        if file_list:
            if '\nsecret_scanner_detailed_report.txt' not in g.read():
                g.write('\nsecret_scanner_detailed_report.txt')


def main(user_path, all_files):
    os.path.normpath(user_path)
    if os.path.isdir(user_path):
        file_list = []
        # check the size of the folder to scan
        if len(glob.glob(user_path+'/**/*', recursive=True)) <= 1000:
            secret_words = generate_words()
            # check if -a/--all flag is used (to include all .gitignore files)
            if not all_files:
                scan_ignore = ignore(user_path)
            else:
                scan_ignore = []

            dot_file_list = scan(user_path+'/**/.*', scan_ignore, secret_words)
            file_list = scan(user_path + '/**/*', scan_ignore, secret_words)

            # merge dot_file_list and file_list
            file_list.extend(dot_file_list)

            # generate output values for different cases
            if not file_list:
                output = "No secrets found, good job! Keep an eye on them anyway as no tool is perfect."
            else:
                output = f"The scanner found {len(file_list)} possible secret exposure(s)." +\
                         "\nYou can see the detailed report in the 'secret_scanner_detailed_report.txt' file " +\
                         "\n(generated in the scanned dir and added to .gitignore)." +\
                         "\nThank you for using Secret Scanner! Hopefully your secrets will  be safe now."
        else:
            output = "The given directory is too large (virtualenv/venv might be the reason)."
        write_output(user_path, file_list, output)
    else:
        print("The given path is not found. Shall we try another one?", file=sys.stdout)


if __name__ == '__main__':
    main(args.path, args.all)
