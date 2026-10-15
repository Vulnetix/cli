import pandas as pd
from sqlalchemy import text


def monthly(engine, month):
~>    return pd.read_sql(f"SELECT * FROM sales WHERE month = '{month}'", engine)


async def by_region(conn, region):
~>    return await conn.fetch("SELECT * FROM sales WHERE region = '" + region + "'")


def totals(session, year):
~>    return session.execute(text("SELECT SUM(amount) FROM sales WHERE year = %s" % year)).scalar()
