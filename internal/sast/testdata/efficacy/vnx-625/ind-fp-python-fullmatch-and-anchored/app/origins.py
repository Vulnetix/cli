import re
from urllib.parse import urlsplit

ALLOWED_HOSTS = {"acme.io", "www.acme.io"}


def is_allowed_origin(origin):
    if re.fullmatch(r"https://([a-z0-9-]+\.)?acme\.io", origin):
        return True
    if re.match(r"^https://([a-z0-9-]+\.)?acme\.io(:\d+)?(/|$)", origin):
        return True
    return urlsplit(origin).hostname in ALLOWED_HOSTS
