from django.http import JsonResponse


def charge(request):
    raw = request.POST.get("amount")
~>    amount = int(raw)
    return JsonResponse({"charged": amount})
