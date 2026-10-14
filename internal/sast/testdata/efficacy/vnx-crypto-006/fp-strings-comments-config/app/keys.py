from Crypto.PublicKey import RSA

# RSA.generate(1024) is too small, use 3072
HELP = "rsa.generate_private_key(public_exponent=65537, key_size=1024) is rejected"


def generate(settings):
    return RSA.generate(settings.key_bits)
