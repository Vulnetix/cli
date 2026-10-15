from django.http import JsonResponse

from .models import Order


def create_order(request):
~>    order = Order.objects.create(**request.POST.dict())
    return JsonResponse({"id": order.pk})
