from flask import request


def current_token():
~>    token = request.headers.get("Authorization").split(" ")[1]
    return token
