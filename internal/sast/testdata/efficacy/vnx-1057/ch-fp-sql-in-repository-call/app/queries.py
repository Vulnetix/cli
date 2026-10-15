def run_report(name, title):
    from app.dbconn import conn
    cur = conn.cursor()
    cur.execute("SELECT * FROM reports WHERE name = ?", (name,))
    return cur.fetchall()
