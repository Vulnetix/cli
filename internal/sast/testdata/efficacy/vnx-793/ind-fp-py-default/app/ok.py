import os

def norm(base, p):
    full = os.path.realpath(os.path.join(base, p))
    if not full.startswith(base):
        raise ValueError("bad")
    return full

def cell(s):
    return s.replace("|", "/", 1)
