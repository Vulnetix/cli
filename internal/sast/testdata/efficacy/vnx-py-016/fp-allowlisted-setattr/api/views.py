from rest_framework.response import Response

from .models import Customer

EDITABLE = {"name", "phone"}


def patch_customer(request, pk):
    customer = Customer.objects.get(pk=pk)
    for key, value in request.data.items():
        if key not in EDITABLE:
            continue
        setattr(customer, key, value)
    customer.save()
    return Response(status=204)


def copy_defaults(customer, defaults):
    for key, value in defaults.items():
        setattr(customer, key, value)
