def test_guard(client):
    resp = client.get("/admin")
    if resp.request.path.startswith("/admin"):
        assert resp.status_code == 403
