from django.http import JsonResponse


def upload(request):
    length = int(request.headers.get("Content-Length", "0"))
~>    body = request.stream.read(length)
    return JsonResponse({"n": len(body)})


def grid(request):
    rows = int(request.GET.get("rows", 10))
    cols = int(request.GET.get("cols", 10))
~>    table = [[0] * cols for _ in range(rows)]
    return JsonResponse({"t": table})
