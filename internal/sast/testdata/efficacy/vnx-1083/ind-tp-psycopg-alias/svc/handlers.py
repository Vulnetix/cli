import psycopg2 as pg
from psycopg2.extras import RealDictCursor


def list_users(event):
~>    conn = pg.connect(dsn=event["dsn"])
    cur = conn.cursor(cursor_factory=RealDictCursor)
    return cur
