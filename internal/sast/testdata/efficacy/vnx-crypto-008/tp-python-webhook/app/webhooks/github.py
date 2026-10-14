import hashlib
import hmac


def verify(request, secret):
    expected = hmac.new(secret, request.body, hashlib.sha256).hexdigest()
    signature = request.headers.get("X-Hub-Signature-256", "")[7:]
~>    if signature != expected:
        raise PermissionError("bad signature")


def verify_inline(body, secret, provided_sig):
~>    return hmac.new(secret, body, hashlib.sha1).hexdigest() == provided_sig


def check_api_key(request, settings):
~>    if request.headers["X-Api-Key"] == settings.api_key:
        return True
    return False
