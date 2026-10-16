class Repo:
    def __init__(self, conn):
        self.conn = conn
        self.cur = conn.cursor()

    def open_cursor(self):
        cur = self.conn.cursor()
        return cur


def stream(conn, q):
    cur = conn.cursor(name="big")
    cur.execute(q)
    yield from cur
    cur.close()
