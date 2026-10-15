import sqlite3


def save(rows):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.executemany("INSERT INTO t VALUES (?, ?)", rows)
    conn.close()
~>    conn.commit()
