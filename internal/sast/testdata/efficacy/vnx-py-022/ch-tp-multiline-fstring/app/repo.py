def find_user(cur, user_id):
~>    cur.execute(
        f"""
        SELECT id, name FROM users WHERE id = {user_id}
        """
    )
    return cur.fetchone()
