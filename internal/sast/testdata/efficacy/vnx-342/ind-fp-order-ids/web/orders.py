def create_order(db, cart):
    last_order_id = db.scalar("SELECT max(id) FROM orders") or 0
    order_id = last_order_id + 1
    request_seq = db.next_request_seq()
    db.execute("INSERT INTO orders (id, total) VALUES (?, ?)", (order_id, cart.total))
    return order_id, request_seq
