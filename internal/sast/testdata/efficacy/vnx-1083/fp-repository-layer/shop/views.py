from django.http import JsonResponse

from shop.repository import OrderRepository


def order_totals(request):
    rows = OrderRepository().totals()
    return JsonResponse({"rows": rows})
