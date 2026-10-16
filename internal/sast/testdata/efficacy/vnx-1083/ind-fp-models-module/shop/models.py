from django.db import connection


def raw_totals():
    with connection.cursor() as cur:
        cur.execute("SELECT 1")
        return cur.fetchone()
