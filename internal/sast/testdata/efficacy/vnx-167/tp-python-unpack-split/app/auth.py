import base64

from flask import request


def basic_auth():
    header = request.headers.get("Authorization", "")
    token = header[len("Basic "):]
~>    user, password = base64.b64decode(token).decode().split(":")
    return user, password


def parse_cookie(raw):
    out = {}
    for part in raw.split(";"):
~>        name, value = part.strip().split("=")
        out[name] = value
    return out


def upstream(addr):
~>    host, port = addr.split(':')
    return host, int(port)


def parse_query(qs):
~>    return dict(item.split("=") for item in qs.split("&"))
