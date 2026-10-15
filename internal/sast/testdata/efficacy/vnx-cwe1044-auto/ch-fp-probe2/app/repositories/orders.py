from django.db import connection

def orders_for(user_id):
    with connection.cursor() as cur:
        cur.execute("SELECT id, total FROM orders WHERE user_id = %s", [user_id])
        return cur.fetchall()
