def helper():
    return 1


~>def migrate(conn):
    cur = conn.cursor()
    cur.execute("CREATE TABLE a (id int)")
    cur.execute("CREATE TABLE b (id int)")
    cur.execute("CREATE TABLE c (id int)")
    cur.execute("CREATE TABLE d (id int)")
    cur.execute("CREATE TABLE e (id int)")
    cur.executemany("INSERT INTO a VALUES (?)", [(1,), (2,)])
    cur.executescript("CREATE INDEX i ON a(id);")
    cur.execute("ANALYZE")
    conn.commit()
