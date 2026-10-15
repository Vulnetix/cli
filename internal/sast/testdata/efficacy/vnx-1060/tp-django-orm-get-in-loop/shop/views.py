from django.http import JsonResponse

from .models import Customer, Item, Order


def recent_orders(request):
    data = []
    for order in Order.objects.order_by("-created")[:100]:
~>        customer = Customer.objects.get(pk=order.customer_id)
~>        items = Item.objects.filter(order_id=order.id).count()
        data.append({"id": order.id, "customer": customer.name, "items": items})
    return JsonResponse({"orders": data})
