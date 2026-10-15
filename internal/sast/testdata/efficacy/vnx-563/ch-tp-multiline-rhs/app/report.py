def monthly(db, month):
~>    query = (
        "SELECT id, total FROM orders "
        "WHERE month = %s AND status = 'paid'"
    )
    query = "SELECT id, total FROM orders WHERE month = %s"
    return db.execute(query, (month,))
