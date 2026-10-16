from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec


def make_dh_parameters():
~>    return dh.generate_parameters(generator=2, key_size=1024)


def make_signing_key():
~>    return dsa.generate_private_key(key_size=1024)


def make_device_key():
~>    return ec.generate_private_key(ec.SECP192R1())
