from django.http import JsonResponse

FEATURE_A = True
FEATURE_B = False


def feature_flag(request):
    flag = request.GET.get("flag", "FEATURE_A")
~>    value = globals()[flag]
    return JsonResponse({"value": value})


def call_handler(request):
~>    handler = globals().get(request.POST["handler"])
    return handler(request)
