SCHEMA = [
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT)",
    "CREATE INDEX IF NOT EXISTS users_email ON users(email)",
]


def create_schema(conn):
    cur = conn.cursor()
    for statement in SCHEMA:
        cur.execute(statement)
    conn.commit()
