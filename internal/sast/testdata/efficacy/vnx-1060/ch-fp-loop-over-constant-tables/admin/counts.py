def table_sizes(cursor, tables):
    sizes = {}
    rows = cursor.execute("SELECT name, n FROM table_stats").fetchall()
    for name, n in rows:
        sizes[name] = n
    cursor.execute("SELECT COUNT(*) FROM audit_log")
    sizes["audit_log"] = cursor.fetchone()[0]
    return sizes


def summarise(session, Order, ids):
    orders = session.query(Order).filter(Order.id.in_(ids)).all()
    for order in orders:
        print(order.id, order.total)
    return orders
