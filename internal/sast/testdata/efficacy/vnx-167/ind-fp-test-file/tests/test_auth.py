import base64

from app.auth import encode_basic


def test_encode_basic_roundtrip():
    header = encode_basic("alice", "s3cret")
    decoded = base64.b64decode(header[6:]).decode()
    user, password = decoded.split(":")
    assert user == "alice"
    assert password == "s3cret"
