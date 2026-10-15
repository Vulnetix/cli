def render(rows):
    header = ", ".join(["id", "name", "email"])
    body = "\n".join(", ".join(str(c) for c in r) for r in rows)
    sql = "SELECT " + ", ".join(cols) + " FROM t WHERE " + " AND ".join(conds)
    path = os.path.join(base, os.path.join(sub, os.path.join(a, os.path.join(b, c))))
    return header + "\n" + body
