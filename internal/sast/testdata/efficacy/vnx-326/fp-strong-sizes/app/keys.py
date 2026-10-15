from cryptography.hazmat.primitives.asymmetric import dsa, dh, ec


def make_dsa():
    return dsa.generate_private_key(key_size=3072)


def make_params(size):
    return dh.generate_parameters(generator=2, key_size=size)


def make_ec():
    return ec.generate_private_key(ec.SECP256R1())


TIMEOUT = 512
buf = bytearray(1024)
