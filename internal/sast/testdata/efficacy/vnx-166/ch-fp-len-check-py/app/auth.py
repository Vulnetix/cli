from flask import request, abort


def current_token():
    parts = request.headers.get("Authorization", "").split(" ")
    if len(parts) != 2:
        abort(401)
    return parts[1]
