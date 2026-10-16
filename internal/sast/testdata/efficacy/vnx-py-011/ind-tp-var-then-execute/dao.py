import sqlite3


def delete_session(token):
    conn = sqlite3.connect("app.db")
    query = "DELETE FROM sessions WHERE token = '" + token + "'"
    cur = conn.cursor()
~>    cur.execute(query)
    conn.commit()
