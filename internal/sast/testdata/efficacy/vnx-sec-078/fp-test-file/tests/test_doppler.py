def test_mask():
    assert mask("dp.pt.@@sample:[A-Za-z0-9]{43}@@").startswith("dp.pt.")
