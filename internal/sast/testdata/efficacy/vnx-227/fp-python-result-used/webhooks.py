import hmac
import bcrypt


def receive(request, secret):
    expected = hmac.new(secret, request.data, "sha256").hexdigest()
    if not hmac.compare_digest(request.headers["X-Signature"], expected):
        abort(403)
    assert bcrypt.checkpw(b"pw", stored)
    ok = (
        hmac.compare_digest(a, b)
    )
    return ok


def matches(a, b):
    return hmac.compare_digest(a, b)
