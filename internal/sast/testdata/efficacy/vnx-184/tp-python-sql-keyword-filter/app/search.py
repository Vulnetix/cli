from flask import abort, request

~>SQL_KEYWORDS = ("--", ";", "union", "drop")


def search(db):
    q = request.args.get("q", "")
    if any(k in q.lower() for k in SQL_KEYWORDS):
        abort(400)
    return db.execute("SELECT * FROM items WHERE name = '" + q + "'")
