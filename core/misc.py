from datetime import datetime

from core.constants import MARKER, ERROR_INCLUDE_LOG
from core.io import get_resource


def checkForErrorLogs(self, response):
    for i in ERROR_INCLUDE_LOG:
        if i in response:
            return True

    return False


def dict_inject_marker(dictionary_orig: dict, replace):
    copy_dict = dictionary_orig.copy()

    for k, v in copy_dict.items():
        copy_dict[k] = v.replace(MARKER, replace)

    return copy_dict


def dump(obj):
    for attr in vars(obj):
        print("obj.%s = %r" % (attr, getattr(obj, attr)))


def get_date_time():
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    return dt_string


def get_web_shell_src(cmd):
    return get_resource("webshell.php").replace("\n", "").strip() % cmd


def get_web_shell_post_cmd_src():
    return get_resource("webshell_log_inject.php").replace("\n", "").strip()
