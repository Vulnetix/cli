import json

from django.http import HttpResponse

from .models import Order


def edit_order(request, order_id):
    payload = json.loads(request.body)
~>    Order.objects.filter(pk=order_id).update(**payload)
    return HttpResponse(status=204)


def new_order(request):
    fields = request.POST.dict()
    fields.pop("csrfmiddlewaretoken", None)
~>    order = Order.objects.create(**fields)
    return HttpResponse(order.pk)
