def test_create():
    u = create_user(email="a@b.c", password="qwerty")
    assert u
