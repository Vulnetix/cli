def test_header(client):
    resp = client.get("/")
    assert resp.headers["Content-Security-Policy"] == "script-src 'nonce-testnonce1'"
