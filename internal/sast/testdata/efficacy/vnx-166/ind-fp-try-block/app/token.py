from flask import request, abort


def bearer_token():
    try:
        scheme, token = request.headers["Authorization"].split(" ", 1)
    except (KeyError, ValueError):
        abort(401)
    return token
