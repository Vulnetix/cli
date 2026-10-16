def insert_all(cur, rows):
    # for r in rows: cur.execute("INSERT ...", r)  would be an N+1
    cur.executemany("INSERT INTO t (a, b) VALUES (%s, %s)", rows)
    note = "for x in xs: cursor.execute(q, (x,))"
    return note


def after_loop(cur, ids):
    wanted = []
    for i in ids:
        wanted.append(i)
    cur.execute("SELECT * FROM t WHERE id = ANY(%s)", (wanted,))
    return cur.fetchall()
