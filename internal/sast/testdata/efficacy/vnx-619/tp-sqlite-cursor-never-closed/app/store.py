import sqlite3


def find_user(db_path, user_id):
    conn = sqlite3.connect(db_path)
~>    cur = conn.cursor()
    cur.execute("SELECT name FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


class OrderRepo:
    def __init__(self, conn):
        self.conn = conn

    def count(self):
~>        c=self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM orders")
        row = c.fetchone()
        return row[0]
