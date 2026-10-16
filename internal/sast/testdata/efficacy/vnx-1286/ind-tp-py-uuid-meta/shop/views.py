import uuid
from django.http import JsonResponse


def lookup(request):
    raw = request.GET["order"]
~>    order_id = uuid.UUID(raw)
    return JsonResponse({"id": str(order_id)})


def length(request):
~>    size = int(request.META["CONTENT_LENGTH"])
    return JsonResponse({"size": size})
