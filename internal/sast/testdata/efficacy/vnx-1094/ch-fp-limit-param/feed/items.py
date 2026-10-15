def page(cur, after_id, size):
    cur.execute(
        "SELECT id, title FROM items WHERE id > %s ORDER BY id LIMIT %s",
        (after_id, size),
    )
    return cur.fetchall()
