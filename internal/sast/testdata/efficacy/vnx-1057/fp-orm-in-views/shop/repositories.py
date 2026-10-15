from django.db import connection


def top_sellers():
    with connection.cursor() as cursor:
        cursor.execute("SELECT product_id, SUM(qty) FROM shop_orderline GROUP BY product_id")
        return cursor.fetchall()
