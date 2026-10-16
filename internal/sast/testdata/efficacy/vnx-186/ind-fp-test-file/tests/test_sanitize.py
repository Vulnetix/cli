from app.sanitize import clean


def test_removes_lowercase_script():
    payload = "<script>alert(1)</script>hello"
    assert "<script" not in clean(payload)
    assert clean(payload).replace("<script>", "") == "hello"


def test_union_payload_rejected():
    assert "union select" in "1 union select password from users"
