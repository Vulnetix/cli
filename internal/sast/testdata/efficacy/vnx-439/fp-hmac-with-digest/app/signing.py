import hashlib
import hmac

SECRET = b"from-config"


def sign(payload: bytes) -> str:
    return hmac.new(SECRET, payload, hashlib.sha256).hexdigest()


def sign_kw(payload):
    mac = hmac.new(
        SECRET,
        payload,
        digestmod=hashlib.sha512,
    )
    return mac.hexdigest()


def one_shot(payload):
    return hmac.digest(SECRET, payload, "sha256")


def verify(a, b):
    return hmac.compare_digest(a, b)
