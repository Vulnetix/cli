def f(rows):
    for r in rows:
        if r:
            out = [
                c
                for c in r
                if c
                if c.ok
                if c.live
                if c.fresh
                if c.big
            ]
    return out
