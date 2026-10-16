from reports import cache, db


def monthly_totals(account_id, month):
    key = f"totals:{account_id}:{month}"
    if account_id:
~>        rows = db.execute(
            "SELECT category, SUM(amount) FROM ledger WHERE account_id = %s AND month = %s GROUP BY category",
            (account_id, month),
        ).fetchall()
        rows = cache.get(key)
        return dict(rows or [])
    return {}
