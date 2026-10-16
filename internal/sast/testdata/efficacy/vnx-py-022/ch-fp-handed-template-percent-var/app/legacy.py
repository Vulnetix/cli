LOOKUP = "SELECT id FROM accounts WHERE owner = '%s'"


def find(conn, owner, name):
    sql = "SELECT * FROM users WHERE name = '%s' AND active = 1"
    cur = conn.cursor()
    cur.execute(sql % name)
    rows = cur.fetchall()
    tmpl = "UPDATE users SET nick = '{}' WHERE id = {}"
    cur.execute(tmpl.format(name, owner))
    return rows
