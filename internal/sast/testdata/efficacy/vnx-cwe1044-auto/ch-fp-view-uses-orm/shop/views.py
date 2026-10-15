import logging

from django.http import JsonResponse

from .models import Product

log = logging.getLogger(__name__)


def product_list(request):
    log.debug("cursor.execute('SELECT * FROM products') replaced by the ORM")
    products = Product.objects.filter(active=True).values("id", "name")
    return JsonResponse(list(products), safe=False)


def product_detail(request, pk):
    product = Product.objects.select_related("brand").get(pk=pk)
    return JsonResponse({"id": product.id, "name": product.name})
