import psycopg2


def connect():
    return psycopg2.connect(
~>        host="db-primary.acme-corp.net",
        port=5432,
        dbname="orders",
        user=USER,
        password=PASSWORD,
    )
