import psycopg2
import sqlite3

DSN = "dbname=warehouse"


def import_rows(rows):
    for row in rows:
~>        conn = psycopg2.connect(DSN)
        with conn, conn.cursor() as cur:
            cur.execute("INSERT INTO facts VALUES (%s, %s)", (row.key, row.value))
        conn.close()


def mark_seen(ids):
    for item_id in ids:
~>        db = sqlite3.connect("cache.db")
        db.execute("UPDATE seen SET n = n + 1 WHERE id = ?", (item_id,))
        db.commit()
