import sqlite3


def vacuum_and_count(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("VACUUM")
    conn.close()
~>    cur.execute("SELECT COUNT(*) FROM events")
    return cur.fetchone()[0]
