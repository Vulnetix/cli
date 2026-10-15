async def load_tags(conn, posts):
    tags = {}
    async for post in posts:
~>        rows = await conn.execute(
            "SELECT name FROM tags WHERE post_id = $1",
            post.id,
        )
        tags[post.id] = rows
    return tags


def load_names(db, ids):
    names = []
    for i, pid in enumerate(ids):
~>        db.execute("SELECT name FROM people WHERE id = %s" % pid)
        names.append(db.fetchone())
    return names
