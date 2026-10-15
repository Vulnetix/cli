import pandas as pd


def monthly(conn, month):
~>    return pd.read_sql_query("SELECT * FROM sales WHERE month = '%s'" % month, conn)
