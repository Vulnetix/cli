from django.db import connection

def top_sellers(n):
    with connection.cursor() as cur:
        cur.execute("SELECT id FROM shop_product ORDER BY sold DESC LIMIT %s", [n])
        return cur.fetchall()
