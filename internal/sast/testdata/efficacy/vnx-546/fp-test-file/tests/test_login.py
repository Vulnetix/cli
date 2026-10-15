def test_login(client):
    # TODO: add a test for CSRF token rotation
    assert client.get("/login").status_code == 200
