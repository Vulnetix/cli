from django.http import JsonResponse

from .models import Product
from .services import report_rows


def report(request):
    return JsonResponse({"rows": report_rows()})


def cheap(request):
    items = Product.objects.filter(price__lt=10).order_by("name")
    return JsonResponse({"items": [p.name for p in items]})
