import hashlib
import hmac


def verify(request, secret):
~>    expected = hmac.new(secret, request.body, hashlib.sha256).hexdigest()
    expected = request.headers.get("X-Signature", "")
    return hmac.compare_digest(expected, request.headers.get("X-Signature", ""))
