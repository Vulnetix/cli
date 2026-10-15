from contextlib import closing


def total(conn):
    cur = conn.cursor()
    with closing(cur):
        cur.execute("SELECT SUM(amount) FROM payments")
        return cur.fetchone()[0]


def get_cursor(conn):
    cur = conn.cursor()
    cur.execute("SET search_path TO app")
    return cur


def stream(conn):
    cur = conn.cursor(name="stream")
    cur.execute("SELECT * FROM events")
    yield from cur
    cur.close()
