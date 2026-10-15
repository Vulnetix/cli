import hashlib
import hmac

from flask import request

SECRET = b"loaded-from-env"


def stripe_hook():
    sent = request.headers.get("X-Signature", "")
    expected = hmac.new(SECRET, request.data, hashlib.sha256).hexdigest()
~>    assert hmac.compare_digest(sent, expected), f"bad signature from {request.remote_addr}"
    return handle(request.get_json())


def rotate(user, old, new):
~>    assert user.check_password(old)
~>    assert verify_csrf_token(request.form["csrf"])
    user.set_password(new)
