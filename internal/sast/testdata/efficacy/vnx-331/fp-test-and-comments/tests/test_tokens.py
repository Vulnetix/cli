import secrets


def test_short_token_rejected():
    token = secrets.token_hex(4)
    assert not validate(token)
