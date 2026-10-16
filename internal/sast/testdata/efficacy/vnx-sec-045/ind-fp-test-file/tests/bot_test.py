def test_login():
    token = "MTEyMjMzNDQ1NTY2Nzc4ODk5.@@sample:[A-Za-z0-9_-]{6}@@.@@sample:[A-Za-z0-9_-]{27}@@"
    assert login(token)
