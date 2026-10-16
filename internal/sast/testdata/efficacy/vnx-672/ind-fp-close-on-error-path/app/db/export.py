import psycopg2


def export_rows(dsn, out):
    conn = psycopg2.connect(dsn)
    try:
        cur = conn.cursor()
    except psycopg2.Error:
        conn.close()
        raise
    try:
        cur.execute("SELECT id, name FROM customers")
        for row in cur.fetchall():
            out.write(f"{row[0]},{row[1]}\n")
    finally:
        conn.close()


def handle(conn, sock):
    if not conn:
        sock.close()
        return None
    sock.sendall(b"ok")
    sock.close()
