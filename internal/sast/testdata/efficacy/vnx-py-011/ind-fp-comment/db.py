def note(cur, uid):
    # cur.execute(f"SELECT * FROM users WHERE id = {uid}")  never do this
    msg = "do not call cursor.execute(f'SELECT {x}') with user data"
    cur.execute("SELECT 1")
    return msg
