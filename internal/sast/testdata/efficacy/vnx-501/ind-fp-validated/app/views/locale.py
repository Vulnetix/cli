from flask import request, session

ALLOWED_LANGS = {"en", "de", "fr"}


def set_locale():
    lang = request.args.get("lang", "en")
    if lang in ALLOWED_LANGS:
        session["lang"] = lang
    return "", 204
