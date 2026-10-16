import os

from flask import abort, request

ALLOWED_LOCALES = {"en_US.UTF-8", "de_DE.UTF-8", "fr_FR.UTF-8"}


def switch_locale():
    lang = request.form.get("lang", "en_US.UTF-8")
    if lang not in ALLOWED_LOCALES:
        abort(400)
    os.environ["LC_ALL"] = lang
    return "ok"
