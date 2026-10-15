import os

from flask import abort, request

ALLOWED_LANGS = {"en_US.UTF-8", "de_DE.UTF-8"}


def set_locale():
    lang = request.form.get("lang", "C")
    if lang not in ALLOWED_LANGS:
        abort(400)
    os.environ["LANG"] = lang
    return "", 204
