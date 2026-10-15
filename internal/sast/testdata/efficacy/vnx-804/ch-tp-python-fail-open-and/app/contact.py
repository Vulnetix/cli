from flask import abort, request

from .captcha_store import lookup


def contact():
    challenge = lookup(request.form.get("captcha_id"))
~>    if challenge is not None and challenge.answer != request.form.get("captcha"):
        abort(400, "wrong captcha")
    send_message(request.form["message"])
    return "", 204


def send_message(text):
    return text
