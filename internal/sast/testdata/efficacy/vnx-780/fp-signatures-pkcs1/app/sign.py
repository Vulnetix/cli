from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Signature import pkcs1_15


def sign(private_key, data):
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def verify(public_key, sig, data):
    public_key.verify(
        sig,
        data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def legacy_sign(key, h):
    return pkcs1_15.new(key).sign(h)
