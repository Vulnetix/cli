import re


def rel(p):
    # anchored removal is VNX-796's shape
    return re.sub(r'^(\.\./)+', '', p)
