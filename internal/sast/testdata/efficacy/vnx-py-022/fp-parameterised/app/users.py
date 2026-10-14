import sqlite3


def find_user(name):
    con = sqlite3.connect("app.db")
    cur = con.cursor()
    cur.execute("SELECT id FROM users WHERE name = ?", (name,))
    cur.execute("SELECT id FROM users WHERE name = '%s'", (name,))
    cur.execute("SELECT id FROM users WHERE name = %(name)s", {"name": name})
    sql = f'SELECT username FROM users WHERE password = ?'
    cur.execute(sql, (name,))
    return cur.fetchall()
