import sqlite3


def find_user(conn, name):
    cur = conn.cursor()
~>    cur.execute(f"SELECT id, email FROM users WHERE name = '{name}'")
    return cur.fetchone()


def delete(conn, uid):
~>    conn.execute("DELETE FROM sessions WHERE user_id = %s" % uid)


def by_role(cursor, role):
~>    cursor.execute("SELECT * FROM users WHERE role = '{}'".format(role))


def by_email(cursor, email):
~>    cursor.execute("SELECT * FROM users WHERE email = '" + email + "'")


def rename(cursor, uid, name):
~>    cursor.execute(
        f"UPDATE users SET name = '{name}' "
        "WHERE id = %d" % uid
    )


def load(conn, script_name):
~>    conn.executescript(open(script_name).read() + f"; DROP TABLE {script_name}")
