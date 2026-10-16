import hashlib


def test_legacy_digest_matches():
    password = "hunter2"
    assert hashlib.sha256(password.encode()).hexdigest() == load_fixture("digest")
