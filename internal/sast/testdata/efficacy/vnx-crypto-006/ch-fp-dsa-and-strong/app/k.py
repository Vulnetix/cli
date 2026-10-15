from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import dsa


def a():
    return dsa.generate_private_key(key_size=1024)


def b():
    return RSA.generate(3072)
