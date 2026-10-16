import sqlite3


def open_cursor(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    return cursor


def iter_rows(conn, sql):
    cur = conn.cursor()
    cur.execute(sql)
    yield from cur
    cur.close()


class Session:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.cur = self.conn.cursor()

    def close(self):
        self.cur.close()
        self.conn.close()
