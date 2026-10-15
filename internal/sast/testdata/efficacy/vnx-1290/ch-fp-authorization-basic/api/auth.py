import base64

from flask import request, abort


def basic_credentials():
    header = request.headers.get("Authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "basic":
        abort(401)
    user, _, password = base64.b64decode(value).decode().partition(":")
    raw = base64.b64decode(request.headers["Authorization"].split()[1])
    return user, password, raw
