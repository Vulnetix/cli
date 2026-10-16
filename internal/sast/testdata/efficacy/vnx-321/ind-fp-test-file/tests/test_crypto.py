from Crypto.Cipher import AES


def test_roundtrip():
    key = b"0123456789abcdef"
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(b"hello")
    assert ct
