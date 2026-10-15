from flask import request


def pair():
    key, sep, value = request.args["kv"].partition("=")
    return {"key": key, "value": value}
