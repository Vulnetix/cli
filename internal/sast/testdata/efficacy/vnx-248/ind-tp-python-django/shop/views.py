import uuid
from decimal import Decimal

from django.http import JsonResponse
from django.shortcuts import get_object_or_404

from .models import Order, Voucher


def order_detail(request):
    raw = request.GET.get("id")
~>    order = get_object_or_404(Order, pk=int(raw))
    return JsonResponse(order.as_dict())


def redeem(request):
~>    voucher_id = uuid.UUID(request.POST["voucher"])
~>    amount = Decimal(request.POST.get("amount"))
    voucher = Voucher.objects.get(public_id=voucher_id)
    voucher.redeem(amount)
    return JsonResponse({"ok": True})
