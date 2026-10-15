import psycopg2


def connect():
    return psycopg2.connect(
        host="db.internal",
        user="postgres",
~>        password="postgres",
        dbname="orders",
    )
