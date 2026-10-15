import os
import time

from django.http import HttpResponse


def throttle(request):
    delay = float(request.GET.get("delay", "0"))
~>    time.sleep(delay)
    return HttpResponse("ok")


def random_blob(request):
    length = int(request.POST["length"])
~>    data = os.urandom(length)
~>    buf = bytearray(length)
    return HttpResponse(data + bytes(buf))


def chunk(request):
~>    return HttpResponse(request.body.read(int(request.GET["n"])))
