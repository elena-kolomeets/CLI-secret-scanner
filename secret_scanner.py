import glob
import os
import argparse

parser = argparse.ArgumentParser(
    prog='Secret Scanner',
    usage='This tool is used for scanning project directory for secrets that should not be shared.'
          'Use -h/--help flag to get more information.',
    description='The program scans the files of the current or specified (with -p/--path) directory for secrets '
                '(password, secret key etc.) that have not been hidden (e.g. added to .env). '
                'By default files added to .gitignore are NOT scanned. You can change it by using the "--all" flag. '
                'After scanning a summary of the results is given'
                'in "secret_scanner_results.txt" file (generated in the scanned dir and added to .gitignore) '
                'and in the terminal (if run in the terminal).',
    epilog='Thank you for using Secret Scanner! Hopefully your secrets are safe now.'
           'The author is Elena Kolomeets (GitHub elena-kolomeets).',
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
    '--all',
    required=False,
    action='store_true',
    help='Use this flag to scan all files, including the files added to .gitignore (not scanned by default)',
)

args = parser.parse_args()


def ignore(user_path):
    """
    Function that checks if dir contains .gitignore
    and returns a list of all ignored files from all subdirs
    """
    gitignore, ignore_list = [], []
    if os.path.exists(user_path + '/.gitignore'):
        with open(user_path + '/.gitignore') as g:
            for line in g:
                if '\n' in line:
                    line = line[:-1]
                if line[-1] == '/':
                    line = line + '*'
                if line[:2] == '**':
                    line = line[2:]
                gitignore.append(line)
        # print(gitignore)
        for i in gitignore:
            i = user_path + '/**/' + i + '*'
            for j in glob.glob(i, recursive=True):
                ignore_list.append(os.path.relpath(j, start=user_path))
        # print(ignore_list)
    return ignore_list


def main(user_path, all_files):
    os.path.normpath(user_path)
    if os.path.isdir(user_path):
        # generate a list of secret words to scan for
        words_case, secret_words = [], []
        for word in ['password', 'pass', 'key', 'credential', 'database_url', 'database-url', 'db_url', 'db-url']:
            words_case.extend((word, word.upper(), word.capitalize()))
        for word in words_case:
            secret_words.extend((word + ':', word + ' :', word + '=', word + ' =', word + ' is'))

        # check if --all flag is used (to include all .gitignore files)
        # get a list of files added to .gitignore (empty list if no .gitignore) to exclude them from scanning
        if not all_files:
            scan_ignore = ignore(user_path)
        else:
            scan_ignore = []

        # scanning the folder for secrets: adding file names
        # and their lines with secrets to list of dictionaries
        file_list, not_open = [], []

        # scanning for files starting with '.' as they are not matched by default with glob.glob
        for dot_name in glob.glob(user_path+'/**/.*', recursive=True):
            if os.path.relpath(dot_name, start=user_path) in scan_ignore:
                continue
            try:
                with open(dot_name, mode='r', encoding='utf-8') as df:
                    for dfile_line in df:
                        for secret_word in secret_words:
                            if secret_word in dfile_line:
                                file_list.append({'file_name': os.path.relpath(dot_name, start=user_path),
                                                  'file_line': dfile_line})
            except Exception:
                # creating the list of files that could not be open
                not_open.append(f"Could not open the file {os.path.relpath(dot_name, start=user_path)}")
                continue

        # scanning the rest of the files
        for name in glob.glob(user_path+'/**/*', recursive=True):
            if os.path.isdir(name) or os.path.relpath(name, start=user_path) in scan_ignore:
                continue
            try:
                with open(name, mode='r', encoding='utf-8') as f:
                    for file_line in f:
                        for secret_word in secret_words:
                            if secret_word in file_line:
                                file_list.append({'file_name': os.path.relpath(name, start=user_path),
                                                  'file_line': file_line})
            except Exception:
                # creating the list of files that could not be open
                not_open.append(f"Could not open the file {os.path.relpath(name, start=user_path)}")
                continue
        if not file_list:
            return "No secrets found, good job! Keep an eye on them anyway as no tool is perfect."
        else:
            return file_list
    else:
        return "The given path is not found. Shall we try another one?"


if __name__ == '__main__':
    print(main(args.path, args.all))
