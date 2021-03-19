# === LOG === #
import signal

HEADER = '\033[95m'
INFO = '\033[94m'
VERBOSE = '\033[96m'
SUCCESS = '\033[92m'
WARNING = '\033[93m'
ERROR = '\033[91m'
ASK = '\033[35m'
NO_COLOR = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

is_verbose = False


def success(log: str):
    print(f"{SUCCESS}{BOLD}[SUCCESS] {log}{NO_COLOR}")


def set_global_verbose(v):
    global is_verbose
    is_verbose = v


def ask(msg: str):
    res = None

    try:
        res = input(f"{ASK}{msg}{NO_COLOR}")
    except EOFError:
        if not msg.startswith("\n"):
            msg = "\n" + msg
        res = ask(msg)

    return res


def verbose(log: str):
    if is_verbose:
        print(f"{VERBOSE}[DEBUG] {log}{NO_COLOR}")


def warn(log: str):
    print(f"{WARNING}[WARNING] {log}{NO_COLOR}")


def info(log: str, bold=False):
    if bold:
        print(f"{INFO}{BOLD}[INFO] {log}{NO_COLOR}")
    else:
        print(f"{INFO}[INFO] {log}{NO_COLOR}")


def err(log: str, exit: bool = False):
    print(f"{ERROR}[CRITICAL] {log}{NO_COLOR}")
    if exit:
        print(f"Leaving now.")
        import sys
        sys.exit(1)
