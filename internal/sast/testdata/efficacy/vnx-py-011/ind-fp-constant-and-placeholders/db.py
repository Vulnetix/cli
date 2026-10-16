from sqlalchemy import text


def fetch_many(cur, ids):
    cur.execute("SELECT COUNT(*) FROM users")
    marks = ", ".join(["?"] * len(ids))
    cur.execute(f"SELECT * FROM users WHERE id IN ({marks})", ids)
    return cur.fetchall()


def named(session, cat):
    return session.execute(text("SELECT * FROM products WHERE category = :c"), {"c": cat})
