from django.http import JsonResponse
from .models import Order


def order_detail(request):
~>    order = Order.objects.get(pk=request.GET["order_id"])
    return JsonResponse({"total": order.total})


def cancel(request):
    order_id = request.POST.get("id")
~>    Order.objects.filter(id=order_id).update(status="cancelled")
    return JsonResponse({"ok": True})
