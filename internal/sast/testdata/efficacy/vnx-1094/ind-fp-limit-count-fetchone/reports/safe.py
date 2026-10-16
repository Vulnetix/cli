def page(cur, start, end):
    cur.execute("SELECT * FROM orders WHERE created_at BETWEEN %s AND %s LIMIT 100", (start, end))
    return cur.fetchall()


def how_many(cur, start, end):
    cur.execute("SELECT COUNT(*) FROM orders WHERE created_at BETWEEN %s AND %s", (start, end))
    return cur.fetchone()[0]


def newest(cur, since):
    cur.execute("SELECT * FROM orders WHERE created_at >= %s ORDER BY created_at DESC", (since,))
    return cur.fetchone()


def top(cur, since):
    cur.execute("SELECT TOP 50 * FROM orders WHERE created_at >= ?", (since,))
    return cur.fetchall()
