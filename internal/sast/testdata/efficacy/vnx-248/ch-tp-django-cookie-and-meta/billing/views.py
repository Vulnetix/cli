from django.http import JsonResponse


def statement(request):
~>    account_id = int(request.COOKIES["account"])
~>    offset = int(request.META.get("HTTP_X_OFFSET", "0"))
    return JsonResponse(load_statement(account_id, offset))
