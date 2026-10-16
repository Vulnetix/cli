import re


def is_allowed_origin(origin):
~>    return re.match(r"^https://dashboard\.acme\.io(:\d+)?", origin) is not None
