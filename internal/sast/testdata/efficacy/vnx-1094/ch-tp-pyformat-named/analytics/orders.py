QUERY = None


def big_orders(cur, params):
    query = (
        "SELECT o.id, o.total FROM orders o "
        "WHERE o.total >= %(min_total)s AND o.placed_at <= %(until)s"
    )
~>    cur.execute(query, params)
    return [dict(r) for r in cur.fetchall()]
