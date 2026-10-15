def load_user(db, user_id):
    """Load a user.

    Args:
        db: Database handle.
~>        userid: The user's primary key.
    """
    return db.get(user_id)
