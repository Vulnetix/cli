import sqlite3


def find_orders(db_path, customer_id):
    conn = sqlite3.connect(db_path)
~>    cur = conn.cursor()
    cur.execute("SELECT id, total FROM orders WHERE customer_id = ?", (customer_id,))
    rows = cur.fetchall()
    return [dict(id=r[0], total=r[1]) for r in rows]
