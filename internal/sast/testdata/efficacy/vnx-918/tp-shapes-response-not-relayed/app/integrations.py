from urllib.request import urlopen

import requests
from django.http import JsonResponse


def ping(request):
    target = request.GET.get("target")
~>    upstream = requests.request("HEAD", target, timeout=10)
    return JsonResponse({"reachable": upstream.ok})


def warm(request):
    target = request.GET["target"]
~>    with urlopen(target) as resp:
        resp.read()
    return JsonResponse({"warmed": True})


def notify(request):
~>    r = requests.post(request.POST.get("callback"), json={"done": True}, timeout=5)
    return JsonResponse({"status": r.status_code})
