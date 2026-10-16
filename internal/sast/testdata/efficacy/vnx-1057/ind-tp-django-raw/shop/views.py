from django.http import JsonResponse
from .models import Product


def product_list(request):
    category = request.GET.get("category", "all")
~>    products = Product.objects.raw("SELECT * FROM shop_product WHERE category = %s", [category])
    return JsonResponse({"n": len(list(products))})
