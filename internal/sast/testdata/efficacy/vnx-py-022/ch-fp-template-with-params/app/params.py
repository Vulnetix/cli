def find(conn, name):
    sql = "SELECT * FROM users WHERE name = %s"
    cur = conn.cursor()
    cur.execute(sql, (name,))
    ids = [1, 2, 3]
    marks = ", ".join(["%s"] * len(ids))
    stmt = "SELECT * FROM users WHERE id IN (%s)"
    cur.execute(stmt % marks, ids)
    return cur.fetchall()
