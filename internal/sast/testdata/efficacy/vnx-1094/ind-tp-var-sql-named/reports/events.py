def events_since(cursor, since):
    sql = "SELECT id, kind FROM events WHERE ts >= %(since)s ORDER BY ts"
~>    cursor.execute(sql, {"since": since})
    rows = []
    for row in cursor.fetchall():
        rows.append(dict(row))
    return rows
