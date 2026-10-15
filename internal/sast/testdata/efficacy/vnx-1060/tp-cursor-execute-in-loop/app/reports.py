import sqlite3


def order_totals(conn: sqlite3.Connection):
    cursor = conn.cursor()
    cursor.execute("SELECT id, customer_id FROM orders")
    rows = cursor.fetchall()
    totals = {}
    for row in rows:
~>        cursor.execute("SELECT SUM(amount) FROM order_lines WHERE order_id = ?", (row[0],))
        totals[row[0]] = cursor.fetchone()[0]
    return totals
