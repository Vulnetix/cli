def test_signature(client, expected_signature):
    resp = client.post("/hook")
    signature = resp.headers["X-Signature"]
    assert signature == expected_signature
