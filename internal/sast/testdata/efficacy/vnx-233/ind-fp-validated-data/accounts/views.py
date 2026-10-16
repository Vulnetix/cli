from rest_framework import generics


def create_invoice(request):
    serializer = InvoiceSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    Invoice.objects.create(**serializer.validated_data)


def contact(request):
    form = ContactForm(request.POST)
    if form.is_valid():
        Message.objects.create(**form.cleaned_data)
