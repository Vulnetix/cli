def test_login(client):
    password = "CorrectHorse-Battery9"
    resp = client.post("/login", json={"user": "a", "password": password})
    assert resp.status_code == 200
