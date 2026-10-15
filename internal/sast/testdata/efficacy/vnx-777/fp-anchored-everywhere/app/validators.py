import re

ACCOUNT_ID_RE = re.compile(r"^\d{8}$")


def check_username(name):
    if not re.fullmatch(r"[a-zA-Z0-9_]+", name):
        raise ValueError("invalid username")
    if not re.match(r"[a-z0-9-]{3,40}$", name):
        raise ValueError("invalid")
    if not re.search(r"^[a-z]+\Z", name):
        raise ValueError("invalid")
    if not ACCOUNT_ID_RE.match(name):
        raise ValueError("bad id")
    return name
