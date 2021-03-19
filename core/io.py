import errno
import os

from core.log import info, warn
from core.str_utils import join_char

RES_FOLDER = "res/"


def write_file(file, c):
    f = open(file, "w")
    f.write(c)
    f.close()


def get_relative_file(file):
    return os.path.join(os.path.dirname(__file__), file)


def get_resource(file):
    return open(get_relative_file(RES_FOLDER + file), "r").read()


def mkdir(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print('Error: Creating directory. ' + directory)


def save(filename, output_dir, content):
    final_content = ""

    if isinstance(content, list):

        if len(content) == 1:
            final_content = content[0]
        else:
            i = 0
            for part in content:
                i = i + 1
                final_content = final_content + "\n" + str(i) + "*" * 100 + "\n" + part

    else:
        final_content = content

    file = join_char(output_dir, filename, "/")

    if not os.path.exists(os.path.dirname(file)):
        try:
            os.makedirs(os.path.dirname(file))
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise

    pass

    try:
        with open(file, "w") as f:
            f.write(final_content)
        info("[+] Saved to: " + file, bold=True)
    except IsADirectoryError:
        file = join_char(file, "index", "/")
        with open(file, "w") as f:
            f.write(final_content)
    except PermissionError:
        warn(f"Permission denied saving {file}")
