def orders_for(cursor, user_ids):
    cursor.execute("SELECT * FROM orders WHERE user_id = ANY(%s)", (list(user_ids),))
    return cursor.fetchall()


def chunked(cursor, ids, size=500):
    rows = []
    for i in range(0, len(ids), size):
        batch = ids[i:i + size]
        cursor.execute("SELECT * FROM orders WHERE user_id IN %s", (tuple(batch),))
        rows.extend(cursor.fetchall())
    return rows
