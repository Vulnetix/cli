from Crypto.Cipher import AES

KAT_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def test_known_answer():
    cipher = AES.new(KAT_KEY, AES.MODE_ECB)
    assert cipher.encrypt(bytes(16)).hex() == "c6a13b37878f5b826f4f8162a1c8d879"
