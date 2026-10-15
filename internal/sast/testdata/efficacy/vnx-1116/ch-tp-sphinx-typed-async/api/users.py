async def load_user(db,
                    user_id: int,
                    include_deleted: bool = False):
    """Load a user row.

    :param db: open database session
    :param int user_id: primary key
~>    :param bool with_deleted: also return soft-deleted rows
    :rtype: dict
    """
    return await db.get(user_id, include_deleted)
