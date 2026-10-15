import sqlite3


def test_index(client):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE post (id INTEGER)")
    assert client.get("/").status_code == 200
