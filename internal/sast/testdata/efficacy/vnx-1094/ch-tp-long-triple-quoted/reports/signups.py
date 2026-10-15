def signups(conn, start, end):
    sql = """
        SELECT u.id,
               u.email,
               u.created_at,
               p.plan
        FROM users u
        JOIN plans p ON p.user_id = u.id
        WHERE u.created_at >= %s
          AND u.created_at < %s
        ORDER BY u.created_at
    """
    with conn.cursor() as cur:
~>        cur.execute(sql, (start, end))
        return cur.fetchall()
