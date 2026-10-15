import os
from django.conf import settings
from django.http import HttpResponse
from flask import send_file, request as flask_request


def download(request):
    name = request.GET.get("file", "")
~>    with open(os.path.join(settings.MEDIA_ROOT, name), "rb") as fh:
        return HttpResponse(fh.read())


def legacy():
~>    return send_file(flask_request.args["path"])
