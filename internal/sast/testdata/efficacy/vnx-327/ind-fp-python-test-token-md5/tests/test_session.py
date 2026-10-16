import hashlib


def test_session_token_format():
    session_token = hashlib.md5(b"fixture").hexdigest()
    assert len(session_token) == 32
