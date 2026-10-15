def test_parse():
    conf = parse("PrivateKey = @@sample:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=@@")
    assert conf.private_key
