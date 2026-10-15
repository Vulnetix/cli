from app.sanitize import strip_scripts


def test_strips_lowercase_script():
    payload = "<script>alert(1)</script>"
    assert "<script>" not in strip_scripts(payload)
    assert strip_scripts(payload).replace("<script>", "") == ""
