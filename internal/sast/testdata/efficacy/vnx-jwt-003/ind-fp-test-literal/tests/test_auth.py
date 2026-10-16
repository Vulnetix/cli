import jwt


def test_roundtrip():
    t = jwt.encode({"a": 1}, "test-secret-literal", algorithm="HS256")
    assert jwt.decode(t, "test-secret-literal", algorithms=["HS256"])["a"] == 1
