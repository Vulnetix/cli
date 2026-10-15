HELP = "for row in rows: cursor.execute(query, (row,))  is an N+1 pattern"


def describe():
    # for user in users: session.query(Address).filter_by(user_id=user.id)
    return HELP
