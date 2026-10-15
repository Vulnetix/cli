def order_totals(cursor, rows):
    ids = [row[0] for row in rows]
    placeholders = ",".join("?" for _ in ids)
    cursor.execute(
        f"SELECT order_id, SUM(amount) FROM order_lines WHERE order_id IN ({placeholders}) GROUP BY order_id",
        ids,
    )
    return dict(cursor.fetchall())


def customers(order_ids):
    orders = Order.objects.filter(id__in=order_ids).select_related("customer")
    for order in orders:
        print(order.customer.name)
