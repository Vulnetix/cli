from rest_framework.response import Response

from .models import Customer
from .serializers import CustomerSerializer


def create_customer(request):
    serializer = CustomerSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    customer = Customer.objects.create(**serializer.validated_data)
    return Response({"id": customer.pk})


def form_create(request, form_class):
    form = form_class(request.POST)
    if form.is_valid():
        Customer.objects.create(**form.cleaned_data)
    return Response(status=201)
