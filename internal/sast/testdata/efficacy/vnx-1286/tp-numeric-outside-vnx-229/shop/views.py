from django.http import JsonResponse


def upload(request):
~>    size = int(request.META["CONTENT_LENGTH"])
    return JsonResponse({"size": size})
