from flask import request


def events_since(cursor):
    since = request.args["since"]
    sql = "SELECT id, kind, payload FROM events WHERE ts >= %(since)s ORDER BY ts"
~>    cursor.execute(sql, {"since": since})
    out = []
    for row in cursor.fetchall():
        out.append(row)
    return out
