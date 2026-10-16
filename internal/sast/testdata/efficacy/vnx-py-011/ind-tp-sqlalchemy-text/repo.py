from sqlalchemy import text


def by_category(session, category):
~>    return session.execute(text(f"SELECT * FROM products WHERE category = '{category}'")).fetchall()
