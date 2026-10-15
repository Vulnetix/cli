from django.http import JsonResponse


def coupons(request):
    count = int(request.GET.get("count", "1"))
    codes = []
~>    for _ in range(count):
        codes.append(make_code())
    return JsonResponse({"codes": codes})
