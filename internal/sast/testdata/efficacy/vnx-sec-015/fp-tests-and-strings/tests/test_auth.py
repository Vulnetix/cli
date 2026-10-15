def test_rejects_none():
    token = jwt.encode({"sub": "x"}, None, algorithm="none")
    header = {"alg": "none", "typ": "JWT"}
    with pytest.raises(InvalidTokenError):
        jwt.decode(token, options={"verify_signature": False})
