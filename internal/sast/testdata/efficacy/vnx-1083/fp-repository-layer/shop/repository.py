from django.db import connection


class OrderRepository:
    def totals(self):
        with connection.cursor() as cur:
            cur.execute("SELECT customer_id, SUM(total) FROM orders GROUP BY customer_id")
            return cur.fetchall()
