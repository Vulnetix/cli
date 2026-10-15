from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec


def dh_params():
~>    return dh.generate_parameters(generator=2, key_size=1024)


def dsa_key():
    return dsa.generate_private_key(
~>        key_size=1024,
    )


def ec_key():
~>    return ec.generate_private_key(ec.SECP192R1())
