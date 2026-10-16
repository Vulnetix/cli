import sqlite3


def get(conn, user_id, status):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    cur.execute(
        "SELECT * FROM orders WHERE user_id = %s AND status = %s",
        (user_id, status),
    )
    return cur.fetchall()
