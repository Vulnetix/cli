from django.db import connection
from django.shortcuts import render

from .models import Product


def product_list(request):
    category = request.GET.get("category", "all")
~>    products = Product.objects.raw("SELECT * FROM shop_product WHERE category = %s", [category])
    return render(request, "shop/list.html", {"products": products})


def sales_report(request):
~>    with connection.cursor() as cursor:
~>        cursor.execute("SELECT SUM(total) FROM shop_order")
        total = cursor.fetchone()[0]
    return render(request, "shop/report.html", {"total": total})
