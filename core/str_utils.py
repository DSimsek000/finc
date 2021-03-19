import random
import re
import string


def nicePrintBool(i):
    if i:
        return "yes"
    return "no"


def contains_words(text, words: list) -> bool:
    for word in words:
        if word in text:
            return True
    return False


def random_str(n=20):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))


def longestCommonSuffix(strs):
    longest_suffix = ""
    shortest_str = min(strs, key=len)

    for i in range(len(shortest_str) - 1, -1, -1):
        if all([x.endswith(shortest_str[i + 1:]) for x in strs]):
            longest_suffix = shortest_str[i + 1:]
        else:
            break
    return longest_suffix


def longestCommonPrefix(strs):
    longest_pre = ""
    shortest_str = min(strs, key=len)
    for i in range(len(shortest_str)):
        if all([x.startswith(shortest_str[:i + 1]) for x in strs]):
            longest_pre = shortest_str[:i + 1]
        else:
            break
    return longest_pre


def remove_prefix(text, prefix):
    return text[text.startswith(prefix) and len(prefix):]


def remove_suffix(text, suffix):
    if suffix and text.endswith(suffix):
        return text[:-1 * len(suffix)]
    return text


def substr(s, start, end, no_greedy=True):
    if no_greedy:
        search = f"{start}(.*?){end}"
    else:
        search = re.findall(r'{}(.*){}'.format(start, end), s, re.DOTALL)

    result = re.search(search, s)

    if result and len(result.groups()) > 0:
        return result.group(1)

    return None


"""
return a+c+b
"""


def join_char(a: str, b: str, ch: str):
    assert (len(ch) == 1)

    if not a.endswith(ch):
        a = a + ch

    if b.startswith(ch):
        b = b[1:]

    return a + b
