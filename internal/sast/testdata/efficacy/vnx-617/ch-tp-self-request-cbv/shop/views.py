from django.views.generic import View
from django.http import JsonResponse


class OrderView(View):
    def post(self, request):
        qty = int(self.request.POST.get("quantity", "0"))
~>        assert 0 < qty <= 100
        order = Order.objects.create(user=request.user, quantity=qty)
~>        assert order.owner == self.request.user
        return JsonResponse({"id": order.id})
