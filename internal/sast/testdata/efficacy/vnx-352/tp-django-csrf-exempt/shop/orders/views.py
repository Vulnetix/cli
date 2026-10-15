from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils.decorators import method_decorator
from django.views import View

from .models import Order


~>@csrf_exempt
@require_POST
def cancel_order(request, order_id):
    Order.objects.filter(pk=order_id, owner=request.user).update(status="cancelled")
    return JsonResponse({"ok": True})


~>@method_decorator(csrf_exempt, name="dispatch")
class RefundView(View):
    def post(self, request, order_id):
        Order.objects.get(pk=order_id).refund()
        return JsonResponse({"ok": True})


def transfer(request):
    return JsonResponse({"ok": True})


~>transfer_view = csrf_exempt(transfer)
