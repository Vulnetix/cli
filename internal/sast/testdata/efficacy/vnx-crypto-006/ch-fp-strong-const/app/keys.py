from cryptography.hazmat.primitives.asymmetric import rsa

MIN_BITS = 1024  # reject anything smaller when parsing peers


def gen(bits=4096):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)
