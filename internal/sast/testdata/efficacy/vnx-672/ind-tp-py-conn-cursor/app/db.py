import sqlite3


def count(path):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM t")
    n = cur.fetchone()[0]
    conn.close()
~>    cur.execute("SELECT 1")
    return n
