def user_roles(cur, user_id):
    cur.execute(
        """
        SELECT u.id, r.name
        FROM users u
        JOIN user_roles ur ON ur.user_id = u.id
        JOIN roles r ON r.id = ur.role_id
        WHERE u.id = %s
        """,
        (user_id,),
    )
    return cur.fetchall()
