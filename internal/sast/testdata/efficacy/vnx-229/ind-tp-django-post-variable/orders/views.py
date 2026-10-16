from django.http import JsonResponse
from django.views.decorators.http import require_POST


@require_POST
def apply_discount(request, order_id):
    order = Order.objects.get(pk=order_id, customer=request.user)
    raw = request.POST.get("discount")
    reason = request.POST.get("reason", "")
~>    pct = float(raw)
    order.total = order.total * (1 - pct / 100)
    order.save()
    return JsonResponse({"total": str(order.total), "reason": reason})
