def join(prefix, rule):
    return "/".join((prefix.rstrip("/"), rule.lstrip("/")))


def host(h):
    return h.lstrip(".")


def ext(name):
    return name.rstrip(".")


def line(s):
    return s.strip()
