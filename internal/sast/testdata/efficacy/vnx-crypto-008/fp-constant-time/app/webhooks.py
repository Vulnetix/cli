import hashlib
import hmac


def verify(request, secret):
    expected = hmac.new(secret, request.body, hashlib.sha256).hexdigest()
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not hmac.compare_digest(signature, expected):
        raise PermissionError("bad signature")
    if signature is None or token == "":
        return False
    return True


def missing(token, signature):
    if token == None:
        return False
    if signature != "":
        return True
