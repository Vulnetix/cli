import sqlite3


def test_many():
    for i in range(100):
        conn = sqlite3.connect(":memory:")
        conn.close()
