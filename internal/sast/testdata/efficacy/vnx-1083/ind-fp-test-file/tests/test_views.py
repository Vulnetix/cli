import sqlite3


def test_view():
    db = sqlite3.connect(":memory:")
    assert db
