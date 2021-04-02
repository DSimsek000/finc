import sys
from enum import Enum

from core.constants import TARGET_DEFAULT_PMA_PATH, TARGET_DEFAULT_FTP_PORT, TARGET_DEFAULT_SSH_PORT, \
    TARGET_DEFAULT_MYSQL_PORT
from core.parse_utils import arr_to_str


def print_all_mode_usage():
    print("Mode\t\tArgs\t\t\tOnly PHP\t\t\tDescription")
    print("-------------------------------------------------------------------------------------------------")
    for m in Mode:
        print(m.print_usage())

    sys.exit(0)


class Mode(Enum):
    all = "all"
    rfi = "rfi"
    data = "data"
    expect = "expect"
    filter = "filter"
    fuzz = "fuzz"
    php_info = "phpinfo"
    proc = "proc"
    log = "log"
    php_input = "input"
    session = "session"

    def __str__(self):
        return self.value

    def get_desc(self):
        desc = ""
        args = 0
        for_php = True

        if self == self.fuzz:
            desc = "Attempt including files with filter-bypass"
            for_php = False
        if self == self.filter:
            desc = "Attempt including files with php://filter"
        if self == self.session:
            desc = "Attempt RCE via PHP Sessions"
        if self == self.php_info:
            desc = "Attempt RCE via phpinfo output. Takes url as argument"
            args = 1
        if self == self.all:
            desc = "Try all modes (default)"
            for_php = False
        if self == self.php_input:
            desc = "Attempt RCE with php://input"
        if self == self.expect:
            desc = "Attempt RCE with expect://"
        if self == self.log:
            desc = f"Attempt RCE by poisoning log files: ftp({TARGET_DEFAULT_FTP_PORT}), ssh({TARGET_DEFAULT_SSH_PORT}), mysql({TARGET_DEFAULT_MYSQL_PORT}), pma(\"{TARGET_DEFAULT_PMA_PATH}\")"
            args = 4
            for_php = False
        if self == self.proc:
            desc = "Attempt RCE with proc environment"
            for_php = False
        if self == self.rfi:
            desc = "Remote file inclusion"
            for_php = False
        if self == self.data:
            desc = "Exploit php data:// wrapper"

        php_target = "yes" if for_php else "no"

        if args:
            desc = str(args) + "\t\t\t" + php_target + "\t\t\t" + desc
        else:
            desc = "\t\t\t" + php_target + "\t\t\t" + desc

        return desc

    def print_usage(self):
        return self.value + "\t\t" + self.get_desc()
