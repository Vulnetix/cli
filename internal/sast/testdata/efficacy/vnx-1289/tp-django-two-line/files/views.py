from django.http import HttpResponseBadRequest


def attach(request):
    name = request.FILES["doc"].name
~>    if name.endswith(".html") or name.endswith(".svg"):
        return HttpResponseBadRequest("not allowed")
    return save(request.FILES["doc"])
