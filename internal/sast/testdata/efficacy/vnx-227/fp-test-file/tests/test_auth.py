import hmac


def test_compare_does_not_raise():
    hmac.compare_digest(b"a", b"b")
