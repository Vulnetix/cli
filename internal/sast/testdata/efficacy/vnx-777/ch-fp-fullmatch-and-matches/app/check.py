import re

ZIP = re.compile(r"[0-9]{5}")


def ok(z):
    return ZIP.fullmatch(z) is not None


def ok2(s):
    return re.match(r"[a-z]+\Z", s) is not None
