import re


def rel(p):
~>    return re.sub(r'^(\.\./)+', '', p)


def rel2(p):
~>    p = re.sub(r"^[./\\]+", "", p)
    return p
