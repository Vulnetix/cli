def find_order(db, order_id):
    cur = db.cursor()
    cur.execute("SELECT id, total FROM orders WHERE id = %s", (order_id,))
    return cur.fetchone()
