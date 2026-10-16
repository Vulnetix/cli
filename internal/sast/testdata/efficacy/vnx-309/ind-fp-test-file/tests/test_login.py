def test_plain_password_fixture(user_factory):
    user = user_factory(password="hunter2")
    form = {"password": "hunter2"}
    assert user.password == form["password"]
