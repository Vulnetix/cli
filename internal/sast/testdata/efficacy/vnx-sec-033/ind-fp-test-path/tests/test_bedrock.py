def test_auth():
    key = "ABSK@@sample:[A-Za-z0-9+/]{130}@@"
    assert key.startswith("ABSK")
