def test_client():
    sid = "SK@@sample:[a-f0-9]{32}@@"
    assert build(sid)
