def ledger_rows(cur, account_id):
    cur.execute(
~>        "SELECT e.* FROM entries e "
        "JOIN accounts a ON a.id = e.account_id "
        "JOIN journals j ON j.id = e.journal_id "
        "JOIN periods p ON p.id = j.period_id "
        "JOIN currencies c ON c.code = e.currency "
        "JOIN users u ON u.id = j.created_by "
        "WHERE a.id = %s",
        (account_id,),
    )
    return cur.fetchall()


def one_liner(cur):
~>    cur.execute("SELECT * FROM a JOIN b ON a.id=b.a JOIN c ON c.id=b.c JOIN d ON d.id=c.d JOIN e ON e.id=d.e JOIN f ON f.id=e.f")
