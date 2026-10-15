from django.http import HttpResponse, JsonResponse

from .models import Cart


def checkout(request, cart_id):
    try:
        cart = Cart.objects.get(pk=cart_id)
        cart.checkout()
    except Cart.DoesNotExist:
~>        return JsonResponse({'message': 'failed', 'status': '500'})
    except PaymentError as exc:
        logger.warning("payment failed: %s", exc)
~>        return HttpResponse("Payment failed: " + str(exc))
    return JsonResponse({'message': 'ok'})
