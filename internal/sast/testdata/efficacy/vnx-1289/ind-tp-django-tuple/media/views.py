import os
from django.http import HttpResponseBadRequest


def attach(request):
    up = request.FILES["attachment"]
    name = up.name
~>    if name.endswith((
        ".exe",
        ".bat",
        ".sh",
    )):
        return HttpResponseBadRequest("blocked")
    handle(up)
