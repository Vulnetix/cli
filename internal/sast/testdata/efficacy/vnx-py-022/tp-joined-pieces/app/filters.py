import sqlite3


def search(db_path, name, city, order):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    clauses = ["SELECT id, name FROM people WHERE 1 = 1"]
    if name:
        clauses.append(f"AND name = '{name}'")
    if city:
        clauses.append("AND city = '" + city + "'")
~>    cur.execute(" ".join(clauses))
    rows = cur.fetchall()

    parts = []
    parts.append("SELECT id FROM people ORDER BY")
    parts.append(order)
    stmt = " ".join(parts)
~>    cur.execute(stmt)
    return rows + cur.fetchall()
