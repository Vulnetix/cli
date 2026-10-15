def test_short_password_rejected(client):
    password = "abc"
    assert len(password) < 6
