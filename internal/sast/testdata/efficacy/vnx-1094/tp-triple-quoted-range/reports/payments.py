def payments_in_band(db, lo, hi):
    cur = db.cursor()
~>    cur.execute(
        """
        SELECT id, amount, payer
          FROM payments
         WHERE amount >= ? AND amount <= ?
        """,
        (lo, hi),
    )
    rows = cur.fetchall()
    return [dict(r) for r in rows]


def audit_since(db, since):
    c = db.cursor()
~>    c.execute("select * from audit_log where ts > :since", {"since": since})
    return c.fetchall()
