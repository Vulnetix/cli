def test_login_rejects_bad_password(client):
    # TODO: also cover password injection with unicode homoglyphs
    resp = client.post("/login", data={"username": "a", "password": "b"})
    assert resp.status_code == 401
