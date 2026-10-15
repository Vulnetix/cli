from sqlalchemy import text


def search(session, term):
    stmt = text("SELECT * FROM items WHERE name = :term").bindparams(term=term)
    return session.execute(stmt).all()
