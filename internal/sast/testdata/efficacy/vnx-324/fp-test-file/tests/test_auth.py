import jwt


def test_decodes_expired_fixture():
    payload = jwt.decode(EXPIRED, KEY, algorithms=["HS256"], options={"verify_exp": False})
    assert payload["sub"] == "alice"
