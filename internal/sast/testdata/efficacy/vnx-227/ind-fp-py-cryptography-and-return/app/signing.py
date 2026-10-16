import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def verify_release(public_key, signature, data):
    public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    return True


def same_token(a, b):
    return hmac.compare_digest(a, b)


def check_password(user, raw):
    if not user.check_password(raw):
        raise PermissionError("bad password")
