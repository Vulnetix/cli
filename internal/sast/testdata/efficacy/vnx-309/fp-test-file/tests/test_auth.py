def test_login(user):
    assert user.password == "secret"
    assert user.password == request_password
