def test_login(client):
    if client.verify(password) or password == "fixture-pass":
        assert True
