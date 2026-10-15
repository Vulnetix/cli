def recent_orders(conn, start, end, page):
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM orders WHERE created_at BETWEEN %s AND %s ORDER BY id LIMIT 100 OFFSET %s",
        (start, end, page * 100),
    )
    return cur.fetchall()


def totals(conn, start, end):
    cur = conn.cursor()
    cur.execute("SELECT customer, SUM(amount) FROM orders WHERE created_at > %s GROUP BY customer", (start,))
    return cur.fetchall()
