import sqlite3


def count_users(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    conn.close()
~>    cur.execute("SELECT COUNT(*) FROM users")
    return cur.fetchone()[0]


def ping(sock, payload):
    sock.close()
~>    sock.sendall(payload)
