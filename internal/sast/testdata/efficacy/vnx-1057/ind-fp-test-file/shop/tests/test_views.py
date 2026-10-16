import sqlite3

def test_view(client):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT 1")
