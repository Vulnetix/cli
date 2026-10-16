import json

from django.http import JsonResponse


def list_orders(request):
    page = request.GET.get("page", "1")
    offset = (int(page) - 1) * 20
    return JsonResponse({"offset": offset})


def update_cart(request):
~>    payload = json.loads(request.body)
    return JsonResponse(payload)
