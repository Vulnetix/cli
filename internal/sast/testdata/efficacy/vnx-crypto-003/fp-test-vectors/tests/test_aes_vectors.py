from Crypto.Cipher import AES

# FIPS-197 appendix C.1 known-answer test: the raw block function is ECB.
KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def test_fips197_vector():
    cipher = AES.new(KEY, AES.MODE_ECB)
    out = cipher.encrypt(bytes.fromhex("00112233445566778899aabbccddeeff"))
    assert out.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
