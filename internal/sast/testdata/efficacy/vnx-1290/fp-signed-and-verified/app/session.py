import base64
import hashlib
import hmac

from flask import abort, request

SECRET = b"from-config"


def user_from_cookie():
    raw = request.cookies.get("session", "")
    payload, _, sig = raw.partition(".")
    expected = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        abort(403)
    return base64.b64decode(payload).decode()
