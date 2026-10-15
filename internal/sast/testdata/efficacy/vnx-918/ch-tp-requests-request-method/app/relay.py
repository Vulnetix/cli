import requests
from django.http import HttpResponse


def relay(request):
    target = request.GET.get("target")
~>    upstream = requests.request("GET", target, timeout=10)
    return HttpResponse(upstream.content)
