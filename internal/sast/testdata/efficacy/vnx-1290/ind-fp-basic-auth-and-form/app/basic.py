import base64
from flask import request


def basic():
    hdr = request.headers["Authorization"].split(" ")[1]
    user, _, pw = base64.b64decode(hdr).decode().partition(":")
    return check(user, pw)


def upload():
    blob = request.form["avatar_b64"]
    return base64.b64decode(blob)


DEFAULT = base64.b64decode("YWRtaW4=")
# base64.b64decode(request.cookies.get("session"))
