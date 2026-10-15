import time

import psycopg2

DSN = "dbname=app"


def connect_with_retry():
    for attempt in range(5):
        try:
            conn = psycopg2.connect(DSN)
            break
        except @@sample:p[s]yc[o]pg[2][.]O[p]er[a]ti[o]na[l]Er[r]or@@:
            time.sleep(2 ** attempt)
    return conn


def first_connection():
    for i in range(3):
        try:
            return psycopg2.connect(DSN)
        except @@sample:p[s]yc[o]pg[2][.]O[p]er[a]ti[o]na[l]Er[r]or@@:
            continue


def poll_forever():
    while True:
        conn = psycopg2.connect(DSN)
        conn.close()
        time.sleep(60)
