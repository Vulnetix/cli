def by_ids(cur, ids):
    placeholders = ",".join("?" for _ in ids)
    cur.execute("SELECT * FROM items WHERE id IN (%s)" % ",".join(["%s"] * len(ids)), ids)
    cur.execute(f"SELECT * FROM items WHERE id IN ({placeholders})", ids)
    return cur.fetchall()
