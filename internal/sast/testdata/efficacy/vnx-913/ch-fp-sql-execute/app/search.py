from flask import request


def search(cursor):
    term = request.args.get("q", "")
    cursor.execute("SELECT * FROM items WHERE name LIKE %s", (term,))
    cursor.executemany("INSERT INTO log(q) VALUES (%s)", [(term,)])
    return cursor.fetchall()
