def open_tasks(cur, status, tag):
    cur.execute("SELECT id FROM tasks WHERE status <> %s AND tag != %s", (status, tag))
    rows = cur.fetchall()
    cur.execute("SELECT id FROM tasks WHERE data->>'owner' = %s", (tag,))
    return rows + cur.fetchall()
