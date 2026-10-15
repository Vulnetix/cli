def fetch_many(conn, ids):
    placeholders = ", ".join(["?"] * len(ids))
    cur = conn.cursor()
    cur.execute("SELECT * FROM items WHERE id IN (%s)" % placeholders, ids)
    return cur.fetchall()


def fetch_named(conn, user_id, status):
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM items WHERE owner = %(owner)s AND status = %(status)s",
        {"owner": user_id, "status": status},
    )
    return cur.fetchall()
