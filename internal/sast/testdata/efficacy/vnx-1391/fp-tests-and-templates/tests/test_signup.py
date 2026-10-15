def test_rejects_weak(client):
    password = "123456"
    r = client.post("/signup", data={"password": "qwerty"})
    assert r.status_code == 400
