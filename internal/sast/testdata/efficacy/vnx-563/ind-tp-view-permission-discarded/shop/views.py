from django.http import JsonResponse
from django.views import View


class OrderDetail(View):
    def get(self, request, order_id):
~>        outcome = self.check_ownership(request.user, order_id)
        outcome = self.load_order(order_id)
        return JsonResponse(outcome.as_dict())

    def check_ownership(self, user, order_id):
        return user.orders.filter(pk=order_id).exists()

    def load_order(self, order_id):
        from shop.models import Order
        return Order.objects.get(pk=order_id)
