def sync(rows, extra):
    for row in rows:
        if row.stale:
~>            for row in extra:
                row.touch()
            continue
        row.save()
