import base64

from flask import request


def basic_login():
    encoded = request.headers.get("Authorization", "")[6:]
    decoded = base64.b64decode(encoded).decode("utf-8")
    username, _, password = decoded.partition(":")
    lang = request.headers.get("Accept-Language", "en").split(",")[0]
    return check(username, password, lang)
