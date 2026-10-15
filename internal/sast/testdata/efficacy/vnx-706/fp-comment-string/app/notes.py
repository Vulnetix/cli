# os.path.commonprefix([base, p]) == base is not a containment check
HINT = "os.path.realpath(p).startswith(base) misses /srv/base2"


def show():
    return HINT
