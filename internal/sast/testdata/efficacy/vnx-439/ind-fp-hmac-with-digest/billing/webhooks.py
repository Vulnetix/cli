import hashlib
import hmac


def sign(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def sign_v2(secret: bytes, body: bytes) -> str:
    mac = hmac.new(
        secret,
        msg=body,
        digestmod=hashlib.sha512,
    )
    return mac.hexdigest()


def sign_fast(secret: bytes, body: bytes) -> bytes:
    return hmac.digest(secret, body, "sha256")


def sign_named(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, digestmod="sha384").hexdigest()
