def run(conn):
    return rollup(conn.cursor())


~>def rollup(cur):
    cur.execute("DELETE FROM daily_totals WHERE day = CURRENT_DATE")
    cur.execute("INSERT INTO daily_totals SELECT * FROM v_today")
    cur.execute("UPDATE customers SET last_seen = now() WHERE id IN (SELECT id FROM v_today)")
    cur.execute("DELETE FROM sessions WHERE expires < now()")
    cur.executemany(
        "INSERT INTO audit (event) VALUES (%s)",
        [("rollup",), ("sessions",)],
    )
    cur.execute("VACUUM daily_totals")
    cur.execute("REFRESH MATERIALIZED VIEW mv_sales")
    cur.execute("SELECT COUNT(*) FROM daily_totals")
    return cur.fetchone()
