import re

USERNAME = re.compile(r"^[a-z0-9_]+$")


def ok(name):
    if re.fullmatch(r"[a-zA-Z0-9_]+", name):
        return True
    return USERNAME.match(name) is not None


def has_digit(s):
    return re.search(r"\d", s) is not None
