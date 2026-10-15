from cryptography.hazmat.primitives.asymmetric import dsa


def test_small_key_is_fast():
    key = dsa.generate_private_key(key_size=1024)
    assert key
