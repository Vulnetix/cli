def test_login(client, user):
    resp = client.post("/login", data={"password": "pw"})
    assert user.password == hashed_pw
