from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def check_release(public_key, signature, payload):
    # cryptography raises InvalidSignature, so the bare call is the check
    public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
    return payload
