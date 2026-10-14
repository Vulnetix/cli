import sqlalchemy as sa
from sqlalchemy import text

from app.models import Paste


def search(session, filter):
~>    return session.query(Paste).filter(text("title = '%s' or content = '%s'" % (filter, filter))).all()


def count(engine, table):
    with engine.connect() as conn:
~>        return conn.execute(text(f"SELECT count(*) FROM {table}")).scalar()


def owner(session, owner_id):
~>    clause = sa.text("owner_id = " + owner_id)
    return session.query(Paste).filter(clause).all()
