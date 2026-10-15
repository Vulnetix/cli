def adults(cur):
    cur.execute("SELECT id, name FROM people WHERE age >= 18 AND created_at > NOW() - INTERVAL '1 day'")
    return cur.fetchall()


def by_country(cur, country):
    cur.execute("SELECT id FROM people WHERE country = %s", (country,))
    return cur.fetchall()
