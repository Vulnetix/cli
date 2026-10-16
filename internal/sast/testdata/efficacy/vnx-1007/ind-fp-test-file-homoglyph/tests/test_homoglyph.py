def test_rejects_mixed_script():
    assert not valid_username("аdmin")
    assert not valid_username("pаypal")
