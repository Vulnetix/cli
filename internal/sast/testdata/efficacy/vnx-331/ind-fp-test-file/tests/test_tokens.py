import secrets


def test_short_token_fixture():
    token = secrets.token_hex(4)
    assert len(token) == 8
