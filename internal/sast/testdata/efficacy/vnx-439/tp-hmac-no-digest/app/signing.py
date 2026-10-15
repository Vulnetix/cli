import hashlib
import hmac

SECRET = b"from-config"


def sign(payload: bytes) -> str:
~>    return hmac.new(SECRET, payload).hexdigest()


def sign_multiline(payload):
~>    mac = hmac.new(
        SECRET,
        payload.encode("utf-8"),
    )
    return mac.hexdigest()


def keyed():
~>    return hmac.new(key=SECRET)
