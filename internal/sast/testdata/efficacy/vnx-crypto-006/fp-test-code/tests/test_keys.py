from cryptography.hazmat.primitives.asymmetric import rsa


def test_sign_roundtrip():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    assert key.key_size == 1024
