from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from .models import Order


@require_POST
~>def cancel_order(request, pk):
    order = get_object_or_404(Order, pk=pk)
    order.delete()
    return redirect("orders")


~>def purge_orders(request):
    Order.objects.filter(status="draft").delete()
    return redirect("orders")


def order_list(request):
    return render(request, "orders.html", {"orders": Order.objects.all()})
