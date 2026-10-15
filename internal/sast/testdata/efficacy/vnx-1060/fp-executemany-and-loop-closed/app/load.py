def load(cursor, records):
    params = []
    for rec in records:
        params.append((rec.id, rec.name))
    cursor.executemany("INSERT INTO people (id, name) VALUES (?, ?)", params)
    for rec in records:
        print(rec)
    cursor.execute("SELECT COUNT(*) FROM people WHERE name = ?", (records[0].name,))
