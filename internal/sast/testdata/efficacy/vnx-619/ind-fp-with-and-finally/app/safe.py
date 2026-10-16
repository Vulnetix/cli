import psycopg2
from contextlib import closing


def get_user(dsn, uid):
    conn = psycopg2.connect(dsn)
    with conn.cursor() as cur:
        cur.execute("SELECT name FROM users WHERE id = %s", (uid,))
        return cur.fetchone()


def count_rows(conn):
    cur = conn.cursor()
    try:
        cur.execute("SELECT count(*) FROM events")
        return cur.fetchone()[0]
    finally:
        cur.close()


def names(conn):
    with closing(conn.cursor()) as cur:
        cur.execute("SELECT name FROM things")
        return [r[0] for r in cur]
