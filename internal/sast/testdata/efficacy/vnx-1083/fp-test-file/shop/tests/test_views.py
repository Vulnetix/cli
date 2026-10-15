from django.db import connection
from django.test import TestCase


class ViewTests(TestCase):
    def test_totals(self):
        with connection.cursor() as cur:
            cur.execute("INSERT INTO orders (customer_id, total) VALUES (1, 5)")
        resp = self.client.get("/orders/totals")
        self.assertEqual(resp.status_code, 200)
