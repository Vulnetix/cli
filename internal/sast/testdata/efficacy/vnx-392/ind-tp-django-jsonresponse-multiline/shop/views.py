import json

from django.http import JsonResponse
from django.views.decorators.http import require_POST

from .models import Cart


@require_POST
def add_to_cart(request, cart_id):
    try:
        cart = Cart.objects.get(pk=cart_id)
        item = json.loads(request.body)
        cart.add(item["sku"], item.get("qty", 1))
    except Cart.DoesNotExist:
~>        return JsonResponse(
            {"success": False, "message": "Cart not found"}
        )
    return JsonResponse({"success": True, "items": cart.count()})
