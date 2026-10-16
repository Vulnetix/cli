ORDER_COLUMN = "name"


def search(conn, name, city):
    cur = conn.cursor()
    clauses = ["SELECT id, name FROM people WHERE 1 = 1"]
    params = []
    if name:
        clauses.append("AND name = ?")
        params.append(name)
    if city:
        clauses.append("AND city = ?")
        params.append(city)
    clauses.append("ORDER BY " + ORDER_COLUMN)
    cur.execute(" ".join(clauses), params)
    rows = cur.fetchall()

    words = ["nightly", "export"]
    words.append(city)
    label = "-".join(words)
    cur.execute("INSERT INTO runs (label) VALUES (?)", (label,))
    return rows
