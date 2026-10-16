from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(["POST"])
def redeem(request):
    code = request.data.get("coupon")
    cart = Cart.for_user(request.user)
~>    if code.upper() in ACTIVE_COUPONS:
        cart.apply(code)
    return Response({"total": cart.total})
