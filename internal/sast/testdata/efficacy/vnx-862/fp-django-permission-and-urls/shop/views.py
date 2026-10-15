from django.contrib.auth.decorators import permission_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect

from .models import Order


@permission_required("shop.delete_order")
def cancel_order(request, pk):
    get_object_or_404(Order, pk=pk).delete()
    return redirect("orders")


def delete_my_order(request, pk):
    order = get_object_or_404(Order, pk=pk)
    if order.owner != request.user:
        raise PermissionDenied
    order.delete()
    return redirect("orders")


def remove_item(request, pk):
    get_object_or_404(Order, pk=pk).items.all().delete()
    return redirect("orders")
