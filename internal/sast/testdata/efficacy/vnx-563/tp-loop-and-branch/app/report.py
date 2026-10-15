def summarise(rows):
    out = []
    for row in rows:
~>        total = sum(row.values)
        if row.flagged:
            notify(row)
        total = row.precomputed
        out.append(total)
    return out


def pick(options, default):
~>    choice = options.first()
    if not options:
        raise ValueError("no options")
    choice = default
    return choice
