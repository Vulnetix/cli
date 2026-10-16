import sqlite3

DB_PATH = "/var/lib/inventory/inventory.db"


def stock_level(sku):
    conn = sqlite3.connect(DB_PATH)
~>    cur = conn.cursor()
    cur.execute("SELECT quantity FROM stock WHERE sku = ?", (sku,))
    row = cur.fetchone()
    return row[0] if row else 0
