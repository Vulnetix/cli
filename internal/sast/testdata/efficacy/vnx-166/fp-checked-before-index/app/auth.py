from flask import request, abort


def current_token():
    header = request.headers.get("Authorization", "")
    if " " not in header:
        abort(401)
    return header.split(" ")[1]


def api_key():
    header = request.headers.get("X-Api-Key", "")
    parts = header.split(":")
    if len(parts) != 2:
        abort(400)
    return parts[1]


def first_only():
    header = request.headers.get("Accept", "")
    return header.split(",")[0]
