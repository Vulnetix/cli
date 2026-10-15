import re


def allowed_origin(origin):
~>    return re.match(r"https://([a-z0-9-]+\.)?example\.com", origin) is not None


def check_host(host):
~>    if not re.search(r"^api\.example\.org", host):
        raise PermissionError(host)
