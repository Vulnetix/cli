import os
from urllib.parse import unquote

from django.http import FileResponse, HttpResponseBadRequest

MEDIA_ROOT = "/srv/media"


def media(request, raw_path):
~>    if ".." in raw_path or raw_path.startswith("/"):
        return HttpResponseBadRequest("invalid path")
    path = unquote(raw_path)
    return FileResponse(open(os.path.join(MEDIA_ROOT, path), "rb"))
