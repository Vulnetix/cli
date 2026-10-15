from flask import request

THEMES = {"dark": 1, "light": 2}


def theme():
    name = request.args.get("theme", "light")
    return THEMES[name]


def headers():
    return request.headers["X-Index"]
