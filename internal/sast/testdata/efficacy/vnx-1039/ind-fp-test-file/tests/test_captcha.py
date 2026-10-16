RECAPTCHA_V3_SECRET = "test"

def test_success_only():
    result = {"success": True}
    assert result["success"]
