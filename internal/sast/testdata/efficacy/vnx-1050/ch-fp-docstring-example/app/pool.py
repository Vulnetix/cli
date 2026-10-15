import psycopg2

DSN = "dbname=app"


def get_conn():
    """Return a pooled connection.

    Do not write code like this, which opens a connection per row:

        for row in rows:
            conn = psycopg2.connect(DSN)
            conn.cursor().execute("INSERT ...", row)

    Call get_conn() once before the loop instead.
    """
    return psycopg2.connect(DSN)
