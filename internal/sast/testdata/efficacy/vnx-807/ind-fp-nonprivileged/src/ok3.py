from flask import request


def render():
    theme = request.cookies.get("theme")
    if theme == "dark":
        return "dark"
    lang = request.args.get("lang")
    if lang:
        return lang
    if request.user.is_staff:
        return "staff"
    return "light"
