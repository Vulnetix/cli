from django.shortcuts import get_object_or_404, render

from .models import Product


def product(request, pk):
    item = get_object_or_404(Product, pk=pk)
    return render(request, "shop/product.html", {"product": item})
