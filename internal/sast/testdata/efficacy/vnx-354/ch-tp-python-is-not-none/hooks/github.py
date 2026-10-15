import hashlib
import hmac

from flask import abort, request


def verify(secret: bytes) -> None:
    body = request.get_data()
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    sig = request.headers.get("X-Hub-Signature-256")
~>    if sig is not None and not hmac.compare_digest(sig, expected):
        abort(401)


def verify_short(secret: bytes, body: bytes, tag: str) -> bool:
~>    if hmac.new(secret, body, hashlib.sha256).hexdigest()[:16] != tag:
        return False
    return True
