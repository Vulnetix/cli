from cryptography.hazmat.primitives.asymmetric import padding


def wrap(public_key, message):
~>    return public_key.encrypt(message, padding.PKCS1v15())
