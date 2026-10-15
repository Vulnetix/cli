def events_between(conn, start, end):
    cur = conn.cursor()
~>    cur.execute("SELECT id, kind, ts FROM events WHERE ts >= %s AND ts < %s ORDER BY ts", (start, end))
    rows = cur.fetchall()
    cur.close()
    return rows
