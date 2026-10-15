import pymysql
from django.db import connections


def legacy_orders(request):
~>    conn = pymysql.connect(
        host="legacy-db",
        user="reader",
        database="orders",
    )
~>    with connections["legacy"].cursor() as cursor:
        cursor.execute("SELECT * FROM orders")
        return cursor.fetchall()
