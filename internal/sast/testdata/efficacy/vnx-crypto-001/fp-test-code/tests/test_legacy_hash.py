import hashlib

from app.accounts import store_password


def test_legacy_rows_still_verify(db):
    legacy = hashlib.md5(b"hunter2").hexdigest()
    db.insert("u", legacy)
    assert store_password(db, "u", "hunter2")
