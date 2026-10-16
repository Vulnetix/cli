def test_parse_token():
    token = "@@sample:npm_[A-Za-z0-9]{36}@@"
    assert token.startswith("npm_")


def test_pypi():
    token = "@@sample:pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{60}@@"
    assert token.startswith("pypi-")
