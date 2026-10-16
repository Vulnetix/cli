from pathlib import Path

from django.http import FileResponse, Http404

BASE = Path("/srv/reports")


def report(request, name):
    target = BASE / name
~>    if not target.is_relative_to(BASE):
        raise Http404()
    return FileResponse(target.open("rb"))
