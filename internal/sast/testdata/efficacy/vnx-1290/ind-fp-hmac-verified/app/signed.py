import base64
import hashlib
import hmac
from flask import request, abort

SECRET = b"k"


def user():
    payload, _, sig = request.cookies.get("session", "").partition(".")
    expected = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        abort(403)
    return base64.b64decode(payload).decode()
