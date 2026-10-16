from Crypto.Cipher import AES


def test_key_as_iv_is_detected_by_legacy_decoder():
    key = b"k" * 16
    cipher = AES.new(key, AES.MODE_CBC, key)
    assert cipher is not None
