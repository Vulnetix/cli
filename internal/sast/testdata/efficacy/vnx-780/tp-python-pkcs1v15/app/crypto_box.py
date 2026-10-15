import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import PKCS1_v1_5 as LegacyCipher


def seal(public_key, message: bytes) -> bytes:
~>    return public_key.encrypt(message, padding.PKCS1v15())


def unseal(private_key, blob: bytes) -> bytes:
    return private_key.decrypt(
        blob,
~>        padding.PKCS1v15(),
    )


def seal_legacy(key, message: bytes) -> bytes:
~>    cipher = LegacyCipher.new(key)
    return cipher.encrypt(message)


def seal_pure(pub, message: bytes) -> bytes:
~>    return rsa.encrypt(message, pub)
