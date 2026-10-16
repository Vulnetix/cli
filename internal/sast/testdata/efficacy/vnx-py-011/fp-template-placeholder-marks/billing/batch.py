def balances(conn, account_ids):
    cur = conn.cursor()
    marks = ", ".join(["?"] * len(account_ids))
    template = "SELECT id, balance FROM accounts WHERE id IN ({})"
    cur.execute(template.format(marks), account_ids)
    banner = "nightly {} run"
    cur.execute("INSERT INTO runs (label) VALUES (?)", (banner.format("batch"),))
    return cur.fetchall()
