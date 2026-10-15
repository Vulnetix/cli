from django.http import JsonResponse


def apply_discount(request, order_id):
    order = Order.objects.get(pk=order_id)
    staff_discount = (
~>        request.COOKIES.get("is_staff", "false") == "true"
    )
    if staff_discount:
        order.total = order.total * 0.5
        order.save()
    return JsonResponse({"total": str(order.total)})
