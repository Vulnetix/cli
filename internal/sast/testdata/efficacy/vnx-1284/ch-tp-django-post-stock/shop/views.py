from django.http import JsonResponse

from .models import Product


def restock(request, pk):
    product = Product.objects.get(pk=pk)
    units = int(request.POST.get("units", "0"))
~>    product.stock += units
    product.save()
    return JsonResponse({"stock": product.stock})
