def test_basic(client):
    r = client.get("/", auth=("admin", "admin"))
    assert r.status_code == 200
