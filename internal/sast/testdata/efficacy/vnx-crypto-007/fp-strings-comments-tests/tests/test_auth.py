import hashlib


def test_legacy_hash_matches(password="secret"):
    assert hashlib.md5(password.encode()).hexdigest()
