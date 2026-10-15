def route(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21):
    """Pick a route.

    The algorithm, in pseudo-code::

        for each candidate:
            if candidate is closed:
                continue
            while queue is not empty:
                if node is visited:
                    skip it
            for each edge of node:
                if edge is cheaper:
                    relax it
    """
    out = 0
    if v0:
        out += 0
    if v1:
        out += 1
    if v2:
        out += 2
    if v3:
        out += 3
    if v4:
        out += 4
    if v5:
        out += 5
    if v6:
        out += 6
    if v7:
        out += 7
    if v8:
        out += 8
    if v9:
        out += 9
    if v10:
        out += 10
    if v11:
        out += 11
    if v12:
        out += 12
    if v13:
        out += 13
    if v14:
        out += 14
    if v15:
        out += 15
    if v16:
        out += 16
    if v17:
        out += 17
    if v18:
        out += 18
    if v19:
        out += 19
    if v20:
        out += 20
    if v21:
        out += 21
    return out
