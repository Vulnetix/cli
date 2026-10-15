import re

# if not re.match(r"[a-z]+", name): raise  <- missing $, fixed below
HELP = 'use re.fullmatch, not if not re.match(r"[a-z]+", name)'


def check(name):
    if not re.fullmatch(r"[a-z]+", name):
        raise ValueError(HELP)
