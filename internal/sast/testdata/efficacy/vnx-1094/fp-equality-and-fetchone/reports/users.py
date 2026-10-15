def user_orders(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE user_id = %s", (user_id,))
    return cur.fetchall()


def latest_after(conn, ts):
    cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE created_at > %s ORDER BY created_at", (ts,))
    return cur.fetchone()
