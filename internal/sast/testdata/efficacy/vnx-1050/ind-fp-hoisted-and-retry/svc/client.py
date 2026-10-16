import time
import requests
import psycopg2


def post_all(events):
    session = requests.Session()
    for e in events:
        session.post(URL, json=e)
    with open("log.txt") as fh:
        for line in fh:
            with open("out.txt", "a") as out:
                out.write(line)


def wait_for_db():
    for attempt in range(10):
        try:
            conn = psycopg2.connect(host="db", dbname="app")
            return conn
        except psycopg2.OperationalError:
            time.sleep(2)
