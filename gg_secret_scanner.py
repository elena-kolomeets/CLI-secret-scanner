import argparse
import glob
import os
import sys
from dotenv import load_dotenv
from pygitguardian import GGClient
from pygitguardian.config import MULTI_DOCUMENT_LIMIT


parser = argparse.ArgumentParser(
    prog='Secret Scanner',
    usage='This tool is used for scanning project directory for secrets that should not be shared.'
          'Run .exe or .py file in your terminal. Use -h/--help flag to get more information.',
    description='The program scans the files of the current or specified (with -p/--path) directory for secrets '
                '(password, secret key etc.) that have not been hidden (e.g. added to .env). '
                'By default files added to .gitignore are NOT scanned. You can change it by using the -a/--all flag. '
                'After scanning a summary of the results is given in "secret_scanner_results.txt" file '
                'and in case secrets are found the detailed report is given in the same file'
                '(generated in the scanned dir and added to .gitignore) '
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
    :return: a list of files to ignore while scanning (empty if no .gitignore)
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
            for j in glob.iglob(i, recursive=True):
                ignore_list.append(os.path.relpath(j, start=user_path))
    return ignore_list


def check(user_path_raw):
    """
    Function that checks and normalizes the path
    given by the user and checks the size of the folder.
    :param user_path_raw:
    :return: True or False
    """
    os.path.normpath(user_path_raw)
    user_path = user_path_raw.replace(os.sep, '/')
    if os.path.isdir(user_path):
        # check the size of the folder to scan
        if len(glob.glob(user_path + '/**/*', recursive=True)) <= 3000:
            return True
        else:
            print("The given directory is too large.")
            return False
    else:
        print("The given path is not found. Shall we try another one?")
        return False


def prepare_for_scan(user_path, scan_ignore):
    """
    Prepare the files for scanning by collecting their names and contents.
    :param user_path: user path
    :param scan_ignore: list of files to ignore
    :return: list of dictionaries with filenames and their contents for scanning
    """
    API_KEY = os.getenv("GG_API_KEY")
    client = GGClient(api_key=API_KEY)
    if client.health_check().success:  # check health of the API and the API key used.
        file_list = []
        for name in glob.iglob(user_path, recursive=True):
            if os.path.isdir(name) or os.path.relpath(name, start=user_path)[6:] in scan_ignore \
                    or os.path.basename(name) == 'gg_secret_scanner_results.txt':
                continue
            try:
                with open(name, mode='r', encoding='utf-8') as file:
                    file_list.append({'filename': os.path.relpath(name, start=user_path)[6:],
                                      'document': file.read()})
            except Exception:
                # continue if some files could not be open (like images or executables)
                continue
        return file_list
    else:
        print('Invalid API Key or API maintenance.')


def scan(file_list):
    """
    Scanning files in the folder and subfolders for secrets in chunks.
    :return: list of results
    """
    if file_list is not None:
        API_KEY = os.getenv("GG_API_KEY")
        client = GGClient(api_key=API_KEY)
        # scan docs in chunks to stay within the size limit
        scanned = []
        for i in range(0, len(file_list), MULTI_DOCUMENT_LIMIT):
            chunk = file_list[i:i+MULTI_DOCUMENT_LIMIT]
            try:
                scan_result = client.multi_content_scan(chunk)
                if scan_result.success:
                    scanned.extend(scan_result.scan_results)
            except Exception as exc:
                print('Could not scan some files. '+str(exc))
        return scanned
    else:
        print('Scanner did not receive documents to scan.')


def write_output(user_path, file_results, file_names):
    """
    Writing the scan output to the terminal and 'gg_secret_scanner_results.txt',
    adding the detailed report of the results to the file,
    adding the file with results  to .gitignore.
    :param user_path:
    :param file_results:
    :param file_names:
    :return: file gg_secret_scanner_results.txt
    """
    count = 0
    output = ''
    # get detailed results
    with open(user_path + '/' + 'gg_secret_scanner_results.txt', mode='w') as f:
        for name, result in zip(file_names, file_results):
            if result.has_secrets:
                count += result.policy_break_count
                if result.policy_break_count > 1:
                    output += f'File "{name}" might have {result.policy_break_count} secrets:' + '\n'
                else:
                    output += f'File "{name}" might have 1 secret:' + '\n'
                for policy_break in result.policy_breaks:
                    for match in policy_break.matches:
                        output += '\t type of secret: ' + match.match_type + ', ' + 'secret: ' + match.match+'\n'
                        if match.line_start is not None:
                            output += f'\t\t(lines: {match.line_start}-{match.line_end})\n'

        # write the total number of secrets to the terminal and at the top of the file
        if count > 1 or count == 0:
            print(f'The scanner found {count} exposed secrets.')
            f.write(f'The scanner found {count} exposed secrets.\n\n')
        else:
            print(f'The scanner found 1 exposed secret.')
            f.write(f'The scanner found 1 exposed secret.\n\n')
        # write detailed results to the file
        f.write(output)

    # add the file to .gitignore
    with open(user_path + '/.gitignore', mode='a+') as g:
        g.seek(0)
        if '\ngg_secret_scanner_results.txt' not in g.read():
            g.write('\ngg_secret_scanner_results.txt')


def main(user_path, all_files):
    """
    The program scans all files in all subdirectories of given directory
    for exposed secrets locally using GitGuardian API.
    Files added to .gitignore can be scanned too (with -a/-all flag).
    The results are written in the terminal and in "gg_secret_scanner_results.txt".
    :param user_path:
    :param all_files:
    :return: execute all functions
    """
    load_dotenv()
    if check(user_path):
        # check if -a/--all flag is used (to include all .gitignore files)
        if not all_files:
            scan_ignore = ignore(user_path)
        else:
            scan_ignore = []
        # get the scan results
        file_list = prepare_for_scan(user_path + '/**/*', scan_ignore)
        file_results = scan(file_list)
        # scanning files starting with '.' (ignored by glob.glob())
        dot_file_list = prepare_for_scan(user_path + '/**/.*', scan_ignore)
        dot_file_results = scan(dot_file_list)
        # merge results for all files
        file_results.extend(dot_file_results)
        # get the file names
        file_names = []
        for i in file_list:
            file_names.append(i['filename'])
        for j in dot_file_list:
            file_names.append(j['filename'])
        write_output(user_path, file_results, file_names)


if __name__ == '__main__':
    main(args.path, args.all)
