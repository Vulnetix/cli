def test_client():
    key = "sk-proj-@@sample:[A-Za-z0-9_-]{60}@@"
    assert make(key)
