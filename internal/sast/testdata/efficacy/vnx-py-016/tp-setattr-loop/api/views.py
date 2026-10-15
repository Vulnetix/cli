from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import Customer


@api_view(["PATCH"])
def patch_customer(request, pk):
    customer = Customer.objects.get(pk=pk)
    for key, value in request.data.items():
~>        setattr(customer, key, value)
    customer.save()
    return Response(status=204)


@api_view(["PUT"])
def put_customer(request, pk):
    customer = Customer.objects.get(pk=pk)
    body = request.data
    for field in body:
~>        setattr(customer, field, body[field])
    customer.save()
    return Response(status=204)
