from django.http import JsonResponse


def order_search(request):
~>    qs = Order.objects.filter(**request.GET.dict())
    return JsonResponse({"orders": list(qs.values("id", "status"))})
