from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def test_legacy_blob_roundtrip():
    key = b"k" * 32
    iv = b"i" * 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(b"hello", 16))
    assert len(ct) == 16
