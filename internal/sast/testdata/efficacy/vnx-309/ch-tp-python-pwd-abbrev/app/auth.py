def check_login(conn, username, passwd):
    row = conn.execute("SELECT id, passwd FROM users WHERE name = ?", (username,)).fetchone()
~>    if row is not None and row["passwd"] == passwd:
        return row["id"]
    return None
