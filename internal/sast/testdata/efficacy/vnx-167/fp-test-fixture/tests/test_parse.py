def test_pair():
    key, value = "a=b".split("=")
    assert key == "a" and value == "b"
