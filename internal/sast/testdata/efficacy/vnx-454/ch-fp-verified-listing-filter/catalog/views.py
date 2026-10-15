from django.http import JsonResponse


def list_sellers(request):
    qs = Seller.objects.all()
    if request.GET.get("verified") == "1":
        qs = qs.filter(verified=True)
    role_filter = request.GET.get("role")
    if role_filter:
        qs = qs.filter(role=role_filter)
    return JsonResponse({"sellers": [s.name for s in qs]})
