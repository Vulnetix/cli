from urllib.request import urlopen

from django.http import HttpResponse


def preview(request):
    target = request.GET["target"]
~>    with urlopen(target) as resp:
        return HttpResponse(resp.read())
