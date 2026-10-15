import sqlite3

conn = sqlite3.connect("app.db")
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER)")
conn.commit()


class Session:
    def open(self):
        self.conn = sqlite3.connect("app.db")
        self.cursor = self.conn.cursor()

    def close(self):
        self.cursor.close()
        self.conn.close()
