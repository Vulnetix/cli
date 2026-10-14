import sqlite3

conn = sqlite3.connect("shop.db")
TABLES = {"orders", "users"}


def count_rows(table):
    if table not in TABLES:
        raise ValueError(table)
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) FROM {table}")
    cur.execute("SELECT 1")
    return cur.fetchone()
