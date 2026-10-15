from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec

DSA_BITS = 3072


def make():
    params = dh.generate_parameters(generator=2, key_size=2048)
    sign_key = dsa.generate_private_key(key_size=DSA_BITS)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    batch = {"key_size": 128, "dsa": "disabled"}
    return params, sign_key, ec_key, batch
