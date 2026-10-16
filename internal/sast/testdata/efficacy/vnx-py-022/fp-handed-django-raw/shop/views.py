from django.shortcuts import render

from .models import Product


def product_search(request):
    name = request.POST.get("name")
    if name:
        sql_query = "SELECT * FROM shop_product WHERE name='" + name + "'"
        print(sql_query)
        results = Product.objects.raw(sql_query)
        more = Product.objects.raw(f"SELECT * FROM shop_product WHERE sku = '{name}'")
        return render(request, "results.html", {"r": results, "m": more})
