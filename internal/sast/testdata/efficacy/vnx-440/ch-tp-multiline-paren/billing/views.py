from django.http import JsonResponse


def refund(request, order_id):
~>    assert (
        request.user.is_authenticated
        and request.user.has_perm("billing.refund")
    ), "refund requires permission"
    order = Order.objects.get(pk=order_id)
    order.refund()
    return JsonResponse({"ok": True})
