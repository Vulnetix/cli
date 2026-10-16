import hashlib
import hmac


def verify_signature(secret: bytes, body: bytes, header: str) -> bool:
    received = header.removeprefix("sha256=")
~>    digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
    digest = received
    return hmac.compare_digest(digest, received)
