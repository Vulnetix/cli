from django.shortcuts import get_object_or_404, render

from .models import Product
from .repositories import top_sellers


def product_list(request):
    # Product.objects.raw("SELECT * FROM shop_product") was replaced by the ORM
    products = Product.objects.filter(active=True).order_by("name")
    return render(request, "shop/list.html", {"products": products})


def product_detail(request, pk):
    product = get_object_or_404(Product, pk=pk)
    help_text = "Run cursor.execute('SELECT 1') to test the connection"
    return render(request, "shop/detail.html", {"product": product, "top": top_sellers(), "help": help_text})
