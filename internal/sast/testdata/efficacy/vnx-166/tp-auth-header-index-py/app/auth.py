from flask import request, abort


def current_token():
~>    token = request.headers.get("Authorization", "").split(" ")[1]
    return token


def api_key():
    header = request.headers["X-Api-Key"]
~>    return header.split(":")[1]
