def by_email(cur, email):
    cur.execute(
        "SELECT * FROM users WHERE email = %(email)s",
        {"email": email},
    )
