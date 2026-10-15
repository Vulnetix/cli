def build(filters):
    query = select(
        table,
        where=and_(
            or_(
                col.a == 1,
                col.b == 2,
                                    # if this were code:
                                    [x for x in rows
                                     if x.ok],
            ),
        ),
    )
    return query
