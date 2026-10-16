from Crypto.Cipher import AES

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def test_nist_sp800_38a_cbc():
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    assert cipher.encrypt(pt).hex() == "7649abac8119b246cee98e9b12e9197d"
