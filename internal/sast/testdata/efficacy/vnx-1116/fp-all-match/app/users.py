def load_user(db, user_id, *, fresh=False):
    """Load a user.

    Args:
        db: Database handle.
        user_id: Primary key.
        fresh: Skip the cache.

    Returns:
        user: The loaded user.
    """
