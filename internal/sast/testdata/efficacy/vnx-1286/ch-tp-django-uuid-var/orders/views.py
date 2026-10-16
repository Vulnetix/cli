import uuid

from django.http import JsonResponse
from .models import Order


def order_detail(request):
    raw_id = request.GET.get("order")
~>    order_id = uuid.UUID(raw_id)
    order = Order.objects.get(pk=order_id)
    return JsonResponse({"id": str(order.pk)})


def page(request):
    p = request.GET.get("page", "1")
    return JsonResponse({"page": int(p)})
