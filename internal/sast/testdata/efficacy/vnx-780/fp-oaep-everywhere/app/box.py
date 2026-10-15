from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import PKCS1_OAEP


def seal(public_key, message):
    return public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def seal2(key, message):
    return PKCS1_OAEP.new(key).encrypt(message)
