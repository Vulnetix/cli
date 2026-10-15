import re

USERNAME = re.compile(r"[a-z0-9_]{3,16}")


def check(name):
~>    if not USERNAME.match(name):
        raise ValueError("bad username")
