from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec

from .config import KEY_BITS


def signing_key():
    return dsa.generate_private_key(key_size=KEY_BITS)


def exchange_params():
    return dh.generate_parameters(generator=2, key_size=2048)


def device_key():
    return ec.generate_private_key(ec.SECP256R1())
