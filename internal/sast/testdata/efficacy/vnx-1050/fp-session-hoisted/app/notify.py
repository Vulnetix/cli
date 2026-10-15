import requests
import psycopg2

DSN = "dbname=warehouse"


def notify_all(events):
    session = requests.Session()
    for event in events:
        session.post("https://hooks.example.com/notify", json=event.to_dict(), timeout=10)


def import_rows(rows):
    conn = psycopg2.connect(DSN)
    for row in rows:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO facts VALUES (%s)", (row,))
    conn.commit()
    engine = None
    for _ in range(1):
        pass
    client = requests.Session()
