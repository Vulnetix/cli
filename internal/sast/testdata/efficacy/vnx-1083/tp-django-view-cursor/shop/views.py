from django.db import connection
from django.http import JsonResponse


def order_totals(request):
~>    with connection.cursor() as cur:
        cur.execute("SELECT customer_id, SUM(total) FROM orders GROUP BY customer_id")
        rows = cur.fetchall()
    return JsonResponse({"rows": rows})


def product_count(request):
~>    cursor = connection.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM products WHERE active = %s", [True]
    )
    return JsonResponse({"count": cursor.fetchone()[0]})
