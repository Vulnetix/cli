def orders_between(conn, start, end):
    cur = conn.cursor()
~>    cur.execute("SELECT * FROM orders WHERE created_at BETWEEN %s AND %s", (start, end))
    return cur.fetchall()
