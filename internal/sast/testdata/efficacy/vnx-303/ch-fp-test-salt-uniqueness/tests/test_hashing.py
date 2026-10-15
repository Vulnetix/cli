from werkzeug.security import generate_password_hash


def test_each_hash_gets_a_new_salt():
    assert generate_password_hash("s3cret") != generate_password_hash("s3cret")
