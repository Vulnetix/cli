from cryptography.hazmat.primitives.asymmetric import dsa, ec
from cryptography.hazmat.primitives.ciphers import algorithms


def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def dsa_key():
    return dsa.generate_private_key(
        key_size=1024,
    )


AES_KEY_SIZE = 256
cipher_alg = algorithms.AES(b"\x00" * 32)
