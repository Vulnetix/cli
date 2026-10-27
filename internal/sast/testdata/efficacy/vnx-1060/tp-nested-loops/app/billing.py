import sqlite3


def invoice_lines(conn: sqlite3.Connection, customers):
    cursor = conn.cursor()
    lines = []
    for customer in customers:
        for invoice_id in customer["invoices"]:
~>            cursor.execute("SELECT * FROM invoice_lines WHERE invoice_id = ?", (invoice_id,))
            lines.extend(cursor.fetchall())
        for region in customer["regions"]:
            for code in region["codes"]:
~>                cursor.execute("SELECT * FROM tariffs WHERE region = ? AND code = ?", (customer["id"], code))
    return lines
