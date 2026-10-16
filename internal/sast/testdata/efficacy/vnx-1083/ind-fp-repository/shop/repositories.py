import sqlite3


def connect():
    return sqlite3.connect("app.db")


def totals(conn):
    cur = conn.cursor()
    cur.execute("SELECT customer_id, SUM(total) FROM orders GROUP BY customer_id")
    return cur.fetchall()
