import sqlite3


def rename_account(db_path, account_id, label):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    template = "UPDATE accounts SET label = '{}' WHERE id = {}"
~>    cur.execute(template.format(label, account_id))
    lookup = "SELECT balance FROM accounts WHERE label = '%s'"
~>    cur.execute(lookup % label)
    conn.commit()
    return cur.fetchone()
