from django.shortcuts import render

from .models import Order


def my_orders(request):
    orders = Order.objects.filter(customer=request.user, status=request.GET.get("status", "open"))
    return render(request, "orders/list.html", {"orders": orders})
