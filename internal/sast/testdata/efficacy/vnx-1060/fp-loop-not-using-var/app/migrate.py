def create_schema(cursor):
    for attempt in range(3):
        try:
            cursor.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY)")
            break
        except Exception:
            continue


def run_statements(conn, statements):
    for _ in statements:
        pass
    conn.execute("VACUUM")
