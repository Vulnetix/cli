from django.http import JsonResponse


def split(request):
    sep = request.GET.get("sep", ",")
    parts = request.GET.get("value", "").split(sep)
    matched = [p for p in parts if p.startswith(request.GET.get("prefix", ""))]
    return JsonResponse({"parts": matched})
