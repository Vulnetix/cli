import psycopg2


def find_user(dsn, user_id):
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name FROM users WHERE id = %s", (user_id,))
            return cur.fetchone()
