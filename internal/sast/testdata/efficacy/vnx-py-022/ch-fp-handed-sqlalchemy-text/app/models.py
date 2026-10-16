from sqlalchemy import text


def search(session, term):
    rows = session.execute(text(f"SELECT * FROM items WHERE name LIKE '%{term}%'"))
    return rows.all()
