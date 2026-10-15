import base64

from django.http import HttpResponse


def login(request):
    raw = request.META["HTTP_AUTHORIZATION"]
    decoded = base64.b64decode(raw[6:]).decode()
~>    username, password = decoded.split(":", 1)
    return HttpResponse(username)


def pair(request):
~>    key, value = request.GET.get("kv").split("=")
    return HttpResponse(key + value)
