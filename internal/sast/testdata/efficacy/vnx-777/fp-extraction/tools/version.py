import re


def major(version):
    m = re.match(r"\d+", version)
    return int(m.group(0)) if m else 0


def leading(text):
    return re.search(r"^[a-z]+", text).group()


def digits(s):
    found = re.findall(r"[0-9]+", s)
    return found
