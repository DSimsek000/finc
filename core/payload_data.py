import json

from core.io import get_relative_file

CORE_JSON = get_relative_file("res/core.json")
REV_SHELL_JSON = get_relative_file("res/revshell.json")


def core_get_by_name(name):
    res = core_get_linux_fuzz_arr()

    for entry in res:
        files = entry['file']

        if isinstance(files, list):
            if name in files:
                return entry
        elif files == name:
            return entry

    return None


def core_get_log_files():
    with open(CORE_JSON) as json_file:
        json_data = json.load(json_file)

        res = json_data['payloads']['linux']['log_files']

    return res


def core_get_linux_fuzz_arr():
    with open(CORE_JSON) as json_file:
        json_data = json.load(json_file)

        res = json_data['payloads']['linux']['fuzz']

    return res


def core_get_home_rel():
    with open(CORE_JSON) as json_file:
        json_data = json.load(json_file)

        res = json_data['payloads']['linux']['home']

    return res


def core_get_proc_files():
    with open(CORE_JSON) as json_file:
        json_data = json.load(json_file)

        res = json_data['payloads']['linux']['proc']

    return res


def core_get_log_files():
    with open(CORE_JSON) as json_file:
        json_data = json.load(json_file)

        res = json_data['payloads']['linux']['log_files']

    return res


def core_get_rev_shell_json_arr() -> list:
    with open(REV_SHELL_JSON) as json_file:
        json_data = json.load(json_file)

    return json_data


def core_get_common_param_names() -> list:
    with open(CORE_JSON) as json_file:
        json_data = json.load(json_file)
        res = json_data['parameters']

    return res


def core_get_common_doc_roots():
    with open(CORE_JSON) as json_file:
        json_data = json.load(json_file)
        res = json_data['payloads']['linux']['document_root']

    return res
