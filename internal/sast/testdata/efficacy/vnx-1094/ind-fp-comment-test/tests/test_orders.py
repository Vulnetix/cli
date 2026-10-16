# cur.execute("SELECT * FROM orders WHERE created_at BETWEEN %s AND %s", (a, b))
def test_range(cur):
    cur.execute("SELECT * FROM orders WHERE created_at BETWEEN %s AND %s", (1, 2))
    assert cur.fetchall() == []
