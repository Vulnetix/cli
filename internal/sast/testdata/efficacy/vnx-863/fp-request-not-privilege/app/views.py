from flask import request


def index():
    if request.headers.get("Authorization"):
        return "has token"
    if request.args.get("tab") == "admin":
        return "admin tab"
    if request.headers.get("Accept") == "application/json":
        return "{}"
    return "html"
