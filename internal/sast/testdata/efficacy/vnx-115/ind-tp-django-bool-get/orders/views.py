from django.http import JsonResponse

from .models import Order


def order_list(request):
~>    gift_only = bool(request.GET.get("gift"))
~>    express = bool(request.POST["express"]) if request.method == "POST" else False
    orders = Order.objects.filter(gift=gift_only, express=express)
    return JsonResponse({"orders": [o.pk for o in orders]})
