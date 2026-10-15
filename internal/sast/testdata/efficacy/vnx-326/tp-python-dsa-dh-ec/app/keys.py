from cryptography.hazmat.primitives.asymmetric import dsa, dh, ec
from Crypto.PublicKey import DSA


def make_dsa():
~>    return dsa.generate_private_key(key_size=1024)


def make_params():
~>    return dh.generate_parameters(generator=2, key_size=512)


def make_ec():
~>    return ec.generate_private_key(ec.SECP192R1())


def make_pycryptodome():
~>    return DSA.generate(1024)
