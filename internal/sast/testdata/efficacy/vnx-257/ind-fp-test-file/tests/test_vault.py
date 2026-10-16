import base64

from app.vault import Vault


def test_roundtrip():
    password = "correct horse battery staple"
    v = Vault(key=b"k" * 32)
    token = v.encrypt(password.encode())
    assert v.decrypt(token) == password.encode()
    assert base64.b64encode(password.encode())
