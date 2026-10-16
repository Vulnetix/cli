def load(cur, oid):
    cur.execute("SELECT * FROM orders o JOIN items i ON i.order_id = o.id WHERE o.id = %s", (oid,))
    a = cur.fetchall()
    cur.execute("SELECT * FROM customers c JOIN addresses a ON a.cid = c.id WHERE c.id = %s", (oid,))
    b = cur.fetchall()
    cur.execute("SELECT * FROM payments p JOIN refunds r ON r.pid = p.id JOIN users u ON u.id = p.uid")
    d = cur.fetchall()
    cur.execute("SELECT * FROM a JOIN b ON b.a = a.id JOIN c ON c.b = b.id")
    return a, b, d, cur.fetchall()
