import glob
import os
from dotenv import load_dotenv
from pygitguardian import GGClient
from pygitguardian.config import MULTI_DOCUMENT_LIMIT


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


def scan(user_path, scan_ignore):
    """
    Scanning the folder for secrets: scanning each folder and subfolder
    and adding file names and their lines with secrets to list of dictionaries
    :param user_path:
    :param scan_ignore: flag
    :return: file_list: list of dictionaries with the results
    """
    load_dotenv()
    API_KEY = os.getenv("GG_API_KEY")
    client = GGClient(api_key=API_KEY)
    if client.health_check().success:   # check health of the API and the API key used.
        file_list = []
        for name in glob.iglob(user_path, recursive=True):
            if os.path.isdir(name) or os.path.relpath(name, start=user_path)[6:] in scan_ignore \
                    or os.path.basename(name) == 'secret_scanner_results.txt' \
                    or os.path.basename(name) == 'secret_scanner_detailed_report.txt':
                continue
            try:
                with open(name, mode='r', encoding='utf-8') as file:
                    file_list.append({'filename': os.path.relpath(name, start=user_path)[6:],
                                      'document': file.read()})
            except Exception:
                # continue scanning if some files could not be open (like images or executables)
                continue

        # scan docs in chunks to stay within the size limit
        scanned = []
        for i in range(0, len(file_list), MULTI_DOCUMENT_LIMIT):
            chunk = file_list[i:i+MULTI_DOCUMENT_LIMIT]
            try:
                scan_result = client.multi_content_scan(chunk)
                if scan_result.success:
                    scanned.extend(scan_result.scan_results)
            except Exception as exc:
                print('Could not scan the files. '+str(exc))
        return scanned
    else:
        print("Invalid API Key or API maintenance")


def main(user_path, all_files):
    """

    :param user_path:
    :param all_files:
    :return:
    """
    if check(user_path):
        # check if -a/--all flag is used (to include all .gitignore files)
        if not all_files:
            scan_ignore = ignore(user_path)
        else:
            scan_ignore = []
        # get the scan results
        file_results = scan(user_path + '/**/*', scan_ignore)
        # scanning files starting with '.' (ignored by glob.glob())
        dot_file_results = scan(user_path + '/**/.*', scan_ignore)

        # print detailed results


if __name__ == '__main__':
    main('.', True)
