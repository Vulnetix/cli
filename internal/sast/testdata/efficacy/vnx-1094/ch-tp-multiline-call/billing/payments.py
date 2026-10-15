def payments_in_window(cursor, lo, hi):
~>    cursor.execute(
        "SELECT id, amount, created_at FROM payments WHERE created_at BETWEEN ? AND ?",
        (lo, hi),
    )
    return cursor.fetchall()
