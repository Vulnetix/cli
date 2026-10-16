import sqlite3
from contextlib import closing


def count_events(db_path, kind):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    with closing(cur):
        cur.execute("SELECT COUNT(*) FROM events WHERE kind = ?", (kind,))
        (n,) = cur.fetchone()
    conn.close()
    return n
