from cryptography.hazmat.primitives.asymmetric import rsa

KEY_BITS = 1024


def short_key():
~>    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def wrapped_key():
    return rsa.generate_private_key(
        public_exponent=65537,
~>        key_size=512,
    )


def from_constant():
~>    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)


def positional():
~>    return rsa.generate_private_key(65537, 768)
