import sqlite3


def big_payments(db_path, floor):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
~>    cur.execute("""
        SELECT id, amount, payer
        FROM payments
        WHERE amount > ?
        ORDER BY amount DESC
    """, (floor,))
    data = cur.fetchall()
    con.close()
    return data
