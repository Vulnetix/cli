def create(request):
    serializer = InvoiceSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    Invoice.objects.create(**serializer.validated_data)
    form = ProfileForm(request.POST)
    if form.is_valid():
        Profile.objects.create(**form.cleaned_data)
