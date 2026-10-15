from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15


def unseal(private_key, ct):
~>    return private_key.decrypt(ct, PKCS1v15())


def sign(private_key, data):
    return private_key.sign(data, PKCS1v15(), hashes.SHA256())
