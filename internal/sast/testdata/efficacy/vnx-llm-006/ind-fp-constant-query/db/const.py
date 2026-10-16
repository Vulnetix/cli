import pandas as pd

QUERY = "SELECT count(*) FROM events"


def total(engine):
    return pd.read_sql(QUERY, engine)
