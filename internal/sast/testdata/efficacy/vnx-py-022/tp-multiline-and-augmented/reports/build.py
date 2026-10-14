def report(cur, start, end, owner):
~>    cur.execute(
        "SELECT * FROM events WHERE ts BETWEEN '%s' AND '%s'" % (start, end)
    )
    rows = cur.fetchall()
    sql = "SELECT * FROM audit WHERE 1=1"
    if owner:
        sql += " AND owner = '" + owner + "'"
~>    cur.execute(sql)
~>    cur.executescript("""
        DELETE FROM tmp WHERE owner = '{}';
    """.format(owner))
    return rows
