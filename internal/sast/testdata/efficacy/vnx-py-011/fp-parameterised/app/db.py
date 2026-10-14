from sqlalchemy import text

from app.models import User


def find_user(cur, session, name, uid):
    cur.execute("SELECT id FROM users WHERE name = %s", (name,))
    cur.execute("SELECT id FROM users WHERE name = ?", [name])
    cur.execute("SELECT id FROM users WHERE name = %(name)s", {"name": name})
    cur.execute("SELECT * FROM t WHERE a LIKE %s", ("%" + name + "%",))
    sql = f'SELECT username from USERS where password = ?'
    cur.execute(sql, (name,))
    rows = User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [name])
    session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": uid})
    query = (
        "SELECT * FROM users "
        "WHERE email = %s"
    )
    cur.execute(query, (name,))
    return rows
