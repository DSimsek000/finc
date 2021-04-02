import base64
import json
import re
import socket
import urllib.parse

from core.constants import MARKER
from core.log import is_verbose
from core.models.req_input import InputRequest
from core.models.sock_address import SockAddress
from core.str_utils import substr


def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return re.match(regex, url) is not None


def is_valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except:
        return False


def is_valid_port(port):
    if not is_int(port):
        return False

    return 1 < int(port) < 65536


def is_int(s):
    try:
        int(s)
        return True
    except:
        return False


def dict_to_str(di: dict):
    res = ""
    for k, v in di.items():
        res = res + f"{k}={v};"

    return res


def arr_to_str(di, sep=","):
    res = ""
    for k in di:
        res = res + k + sep

    if res:
        res = res[:-1]

    return res


def dict_val_count(dictionary: dict, search):
    i = 0
    for k, v in dictionary.items():
        if search in v:
            i = i + 1
    return i


"""
return list
"""


def parse_socket_address(p):
    p = p.strip()
    spl = p.split(":")
    res = SockAddress()

    if spl[0] == "localhost":
        spl[0] = "127.0.0.1"

    if is_valid_ip(spl[0]):
        res.ip = spl[0]
    else:
        return None
    if is_valid_port(spl[1]):
        res.port = int(spl[1])
    else:
        return None

    return res


def parse_get_params_from_url(url: str):
    parsed = urllib.parse.urlparse(url)

    dict_get_data = urllib.parse.parse_qs(parsed.query)

    for k, v in dict_get_data.items():
        dict_get_data[k] = v[0]

    return dict_get_data


"""
parse "a=b;c=d;.."
"""


def str_to_dict(input: str):
    res = {}
    if input:
        for spl in input.split(";"):
            try:
                spl1 = spl.split("=")
                res[spl1[0]] = spl1[1]
            except Exception:
                pass
    return res


"""
extracts get params from url and return url without params
"""


def parse_get_url(tmp_url) -> list:
    res = []
    parsed = urllib.parse.urlparse(tmp_url)
    res.append(parsed.scheme + "://" + parsed.netloc + parsed.path)

    dict_get_data = urllib.parse.parse_qs(parsed.query)

    for k, v in dict_get_data.items():
        dict_get_data[k] = v[0]

    res.append(dict_get_data)
    return res


# B64

def replace_b64_strings(s: str):
    possible_results = re.findall(
        "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", s)

    for base64_enc in possible_results:
        try:
            s = s.replace(base64_enc, base64_decode_utf_8(base64_enc))
        except Exception as e:
            print(str(e))
    return s


def extract_cmd_response(s: str):
    return substr(s, "<result>", "</result>")


def decode_possible_base64_strings(s):
    res = []
    possible_results = get_possible_base64_strings(s)

    for b64 in possible_results:
        base64_dec = base64_decode_utf_8(b64)
        if base64_dec:
            res.append(base64_dec)
    return res


def get_possible_base64_strings(s):
    possible_results = re.findall(
        "(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", s)
    res = []
    for base64_enc in possible_results:
        if base64_enc:
            res.append(base64_enc)

    return res


def base64_encode_utf_8(s):
    return base64.b64encode(bytes(s, "utf-8")).decode("utf-8")


def base64_decode_utf_8(s):
    try:
        return base64.b64decode(s).decode('utf-8')
    except Exception:
        return None


def parse_etc_passwd(file_content):
    folders = re.findall("([^:]*:){6}", file_content)
    all_folders = [x[:-1] for x in folders]
    return all_folders


# Http

# return true if one marker is found (look in cookies, headers, data & params)
def validate_marker(req: InputRequest):
    i = dict_val_count(req.cookies, MARKER) + dict_val_count(req.json, MARKER) + dict_val_count(
        req.extra_headers, MARKER) + dict_val_count(
        req.data, MARKER) + dict_val_count(req.params, MARKER) + int(MARKER in req.url_script_path)
    return i


def parse_request(request_file) -> InputRequest:
    options = InputRequest()

    request = open(request_file, "r").read().strip()

    # === Local Scope === #
    scheme = "http://"
    path = ""
    data = ""
    # === Local Scope === #

    for line in request.splitlines():

        if re.findall(r"Host: " + "(.*)", line):
            options.host = "".join(
                [str(i) for i in re.findall(r"Host: " + "(.*)", line)])
        elif re.findall(r"Cookie: " + "(.*)", line):
            cookies = "".join(
                [str(i) for i in re.findall(r"Cookie: " + "(.*)", line)])

            for spl in cookies.split(";"):
                spl = spl.strip().split("=", 1)

                if len(spl) == 2:
                    options.cookies[spl[0]] = spl[1]
                else:
                    is_verbose(f"Invalid cookie given <'{spl}'>")

        elif "HTTP/" in line:

            path = line[4:].split("HTTP/")[0].strip()

            options.method = line.split("/")[0].strip().upper()

        elif not re.match("[^\"]*:\s*(.*)", line):

            data = data + line

        else:
            if re.findall(r"Referer: " + "(.*)", line):
                referer = "".join(
                    [str(i) for i in re.findall(r"Referer: " + "(.*)", line)])
                if "https://" in referer:
                    scheme = "https://"

            spl = line.split(":", 1)

            if len(spl) == 2:
                options.extra_headers[spl[0].strip()] = spl[1].strip()
            else:
                is_verbose(f"Invalid header given <'{line}'>")

    tmp_url = scheme + options.host + path

    t = parse_get_url(tmp_url)

    options.url_script_path = t[0]
    options.params = t[1]

    # parse body

    try:
        json_object = json.loads(data)
        options.json = json_object
    except Exception:

        if data:
            for spl in data.split("&"):
                spl = spl.strip().split("=", 1)

                if len(spl) == 2:
                    options.data[spl[0]] = spl[1]
                else:

                    is_verbose(f"Invalid data given <'{data}'>")

    return options
