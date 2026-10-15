def shape(groups):
    for g in groups:
        if g.enabled:
            for part in g.parts:
                rows = [
                    fmt(r)
                    for r in part.rows
                    if r.active
                        and r.visible
                ]
                emit(rows)
