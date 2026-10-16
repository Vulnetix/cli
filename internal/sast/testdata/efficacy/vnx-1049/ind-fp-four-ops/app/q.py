def find(cur, uid):
    cur.execute("""
        SELECT u.id, t.name, o.name
        FROM users u
        JOIN teams t ON t.id = u.team_id
        JOIN orgs o ON o.id = t.org_id
        LEFT JOIN plans p ON p.org_id = o.id
        WHERE u.id IN (SELECT user_id FROM active_users)
    """)
    return cur.fetchall()
