from flask import request

THEMES = {"dark": 1, "light": 2}


def listing(rows):
    offset = int(request.args.get("offset", 0))
    return rows[offset:offset + 20]


def theme():
    name = request.args.get("theme", "dark")
    return THEMES[name]
