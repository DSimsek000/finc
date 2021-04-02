ERROR_INCLUDE_LOG = {
    "Warning:",
    "failed to open stream",
    "No such file or directory in",
    "Failed opening",
    "Permission denied in"
}
STABLE_URL_CONTENT = {
    "https://filesamples.com/samples/document/txt/sample1.txt": "Refert tamen, quo modo"
}

LOG_CONTENT_STABLE = "Content is stable"
LOG_CONTENT_NOT_STABLE = "Content is not stable"
LOG_DYNAMIC_PARAMETER = "Parameter is dynamic"
LOG_STACKTRACE_ON = "Stacktrace enabled"

MARKER = "FINC"

SAVE_FOLDER_NAME = "includes"

PHP_EXPECT_WRAPPER = "expect://"
PHP_INPUT = "php://input"

WEB_SHELL_RESPONSE_HEADER = "result"

# RCE Constants ------------------------------------------------------------------------ #
RCE_SSH_LOG = 1
RCE_HTTP_LOG = 2
RCE_PROC_ENV = 3
RCE_PROC_FD = 4
RCE_VIA_SSH_KEYS = 5
RCE_VIA_MYSQL_LOG = 6
RCE_VIA_PMA_LOG = 7
RCE_FTP_LOG = 8
RCE_CPANEL_LOG = 9
RCE_SESSION = 10
RCE_MAIL = 11

WEB_SHELL_PARAM_MISSING = "Param missing."
WEB_SHELL_PARAM_NAME = "cmd"

# Defaults

DEFAULT_TCP_PORT = 11234
DEFAULT_HTTP_PORT = 8000

TARGET_DEFAULT_SSH_PORT = 22
TARGET_DEFAULT_FTP_PORT = 21
TARGET_DEFAULT_MYSQL_PORT = 3306
TARGET_DEFAULT_PMA_PATH = "/phpmyadmin"
