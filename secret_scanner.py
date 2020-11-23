import glob
import os
import argparse

parser = argparse.ArgumentParser(
    prog='Secret Scanner',
    usage='This tool is used for scanning project directory for secrets that should not be shared.',
    description='The program scans the files of the current or specified directory for secrets '
                '(password, secret key etc.) that have not been hidden (e.g. added to .env). '
                'By default files added to .gitignore are NOT scanned. You can change it by using the corresponding '
                'parameter. After scanning a summary of the results is given'
                'in "secret_scanner_results.txt" file (generated in the scanned dir and added to .gitignore) '
                'and in the terminal (if run in the terminal).',
    epilog='Thank you for using Secret Scanner! Hope your secrets are safe now.'
           'The author is Elena Kolomeets (GitHub elena-kolomeets).',
)
parser.add_argument(
    '-p', '--path',
    type=str,
    default='.',
    required=False,
    help='Provide the path to the directory that needs to be scanned for secrets. '
         'By default the current directory is used.',
    metavar='Path',
)
args = parser.parse_args()

# ADD generate txt file and add it to .gitignore


def ignore(user_path):
    """
    Function that checks if dir contains .gitignore
    and returns a list of all ignored files from all subdirs
    """
    # MODIFY THE FUNCTION - NO LOOPS ?
    ignore_list = []
    gitignore = []
    if os.path.exists(user_path + '/.gitignore'):
        with open(user_path + '/.gitignore') as g:
            for line in g:
                if '\n' in line:
                    line = line[:-1]
                if line[-1] == '/':
                    line = line + '*'
                gitignore.append(line)
        # print(gitignore)
        for i in gitignore:
            i = user_path + '/' + i + '*'
            for j in glob.glob(i, recursive=True):
                ignore_list.append(os.path.normpath(j))
        # print(ignore_list, len(ignore_list))
    return ignore_list


def main(user_path):
    os.path.normpath(user_path)
    if os.path.isdir(user_path):
        # get a list of files added to .gitignore (empty if no .gitignnore)
        scan_ignore = ignore(user_path)

        # scanning the folder for secrets: adding file names and contents to list of dictionaries
        file_list = []
        for name in glob.glob(user_path+'/**/*', recursive=True):
            if os.path.isdir(name) or os.path.normpath(name) in scan_ignore:
                continue
            try:
                with open(name, mode='r', encoding='utf-8') as f:
                    file_list.append({'file_name': os.path.basename(name), 'file_content': f.read()})
            except UnicodeDecodeError:
                # return f"Could not open the file {os.path.basename(name)}"
                continue
        return [file['file_name'] for file in file_list]
    else:
        return "Specified path not found. Try another one."


if __name__ == '__main__':
    print(main(args.path))
