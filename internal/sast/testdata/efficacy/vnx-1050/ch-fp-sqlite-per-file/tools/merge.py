import glob
import sqlite3


def count_rows(pattern):
    total = 0
    for db_path in glob.glob(pattern):
        conn = sqlite3.connect(db_path)
        total += conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn.close()
    return total
