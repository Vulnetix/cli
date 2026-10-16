def stream(cur, start, end):
    cur.execute("SELECT * FROM orders WHERE created_at BETWEEN %s AND %s", (start, end))
    while True:
        chunk = cur.fetchmany(500)
        if not chunk:
            break
        yield chunk


def by_customer(cur, cid):
    cur.execute("SELECT * FROM orders WHERE customer_id = %s", (cid,))
    return cur.fetchall()


def orm(session, since):
    return session.query(Order).filter(Order.created_at >= since).all()
