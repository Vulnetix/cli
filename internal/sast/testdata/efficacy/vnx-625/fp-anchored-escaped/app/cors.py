import re

ORIGIN = re.compile(r"^https://([a-z0-9-]+\.)?example\.com$")


def allowed_origin(origin):
    return ORIGIN.match(origin) is not None


def next_url(url):
    return re.match(r"^https://accounts\.example\.com/", url)


def host_ok(host):
    return re.fullmatch(r"([a-z]+\.)?example\.com", host) is not None


def strict(origin):
    return re.match(r"^https://example\.com(:\d+)?$", origin)
