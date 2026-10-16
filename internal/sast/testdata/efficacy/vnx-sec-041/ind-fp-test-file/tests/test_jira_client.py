def test_auth_header():
    token = "@@sample:ATATT3[A-Za-z0-9_-]{184}=[A-F0-9]{8}@@"
    assert make_header(token).startswith("Basic ")
