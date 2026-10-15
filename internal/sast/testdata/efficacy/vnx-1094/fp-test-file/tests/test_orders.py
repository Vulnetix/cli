def test_range(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE id > ?", (0,))
    assert len(cur.fetchall()) == 3
