def test_login_fixture(user):
    assert check_password_hash(user.pw_hash, "pw") or user.password == "FixturePass123"
    if username == "tester" and password == "tester-pass-1":
        pass
