import psycopg2


def db_ping(dsn):
    conn = psycopg2.connect(dsn, connect_timeout=2)
    cur = conn.cursor()
    cur.execute("SELECT 1")
    ok = cur.fetchone() == (1,)
    conn.close()
    return ok
