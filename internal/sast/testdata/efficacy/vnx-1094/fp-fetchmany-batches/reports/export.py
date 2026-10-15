def export_range(conn, start, end, sink):
    cur = conn.cursor()
    # cur.execute("SELECT * FROM t WHERE ts BETWEEN %s AND %s") then fetchall() would load everything
    cur.execute("SELECT * FROM orders WHERE created_at BETWEEN %s AND %s", (start, end))
    while True:
        batch = cur.fetchmany(500)
        if not batch:
            break
        sink.write(batch)
