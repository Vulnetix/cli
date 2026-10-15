def test_login(client):
    password = "password"
    r = client.post("/login", data={"username": "admin", "password": "admin"})
    assert r.status_code == 200
