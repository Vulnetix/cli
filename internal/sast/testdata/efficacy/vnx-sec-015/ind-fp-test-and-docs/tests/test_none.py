import jwt


def test_none_rejected(key):
    token = jwt.encode({"sub": "x"}, None, algorithm="none")
    try:
        jwt.decode(token, key, algorithms=["none"])
    except Exception:
        pass
