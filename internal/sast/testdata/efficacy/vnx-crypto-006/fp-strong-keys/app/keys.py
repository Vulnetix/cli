from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa


def strong():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def strong_wrapped():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def legacy():
    return RSA.generate(3072)
