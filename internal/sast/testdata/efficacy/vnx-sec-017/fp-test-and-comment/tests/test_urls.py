def test_rejects_ftp():
    assert not is_https("ftp://files.acme.io/pub")
