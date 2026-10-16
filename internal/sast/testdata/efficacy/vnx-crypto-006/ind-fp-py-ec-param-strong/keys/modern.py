from cryptography.hazmat.primitives.asymmetric import ec, rsa
from Crypto.PublicKey import RSA


def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def rsa_key(key_size: int):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def strong():
    return RSA.generate(4096)
