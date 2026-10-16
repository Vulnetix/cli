from Crypto.PublicKey import RSA


def test_small_key_is_fast():
    key = RSA.generate(1024)
    assert key.size_in_bits() == 1024
