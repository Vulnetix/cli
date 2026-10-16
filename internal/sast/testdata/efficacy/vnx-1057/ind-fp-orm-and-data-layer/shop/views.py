from django.shortcuts import render
from .models import Product
from . import repositories


def product_list(request):
    products = Product.objects.filter(active=True).order_by("name")
    top = repositories.top_sellers(5)
    # cursor.execute("SELECT 1")
    note = "SELECT * FROM shop_product"
    return render(request, "list.html", {"p": products, "top": top, "note": note})
