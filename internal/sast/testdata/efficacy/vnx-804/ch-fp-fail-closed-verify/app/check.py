from flask import abort, request

from .store import captcha_store


def require_captcha():
    entry = captcha_store.pop(request.form.get("captcha_id"), None)
    if not entry or entry.answer != request.form.get("captcha"):
        abort(400)
    if entry is None or entry.answer != request.form.get("captcha"):
        abort(400)
