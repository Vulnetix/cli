import sqlite3


def test_each_row(rows):
    for row in rows:
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE t (x)")
        db.close()
