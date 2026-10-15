from django.http import JsonResponse


def window(request):
~>    upper = int(request.GET.get("range").split("-")[1])
    return JsonResponse({"upper": upper})
