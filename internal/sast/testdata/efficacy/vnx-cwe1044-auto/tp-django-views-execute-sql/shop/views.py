from django.db import connection
from django.http import JsonResponse

from .models import Product


def report(request):
    with connection.cursor() as cursor:
~>        cursor.execute(
            "SELECT category, SUM(price) FROM shop_product GROUP BY category"
        )
        rows = cursor.fetchall()
    return JsonResponse({"rows": rows})


def cheap(request):
    items = Product.objects.raw("SELECT * FROM shop_product WHERE price < 10")
    return JsonResponse({"items": [p.name for p in items]})
