import os

from django.http import HttpResponseForbidden, FileResponse

STATIC_ROOT = "/srv/portal/private"


def private_asset(request):
    requested = request.path
~>    if requested == "/private/payroll.csv" and not request.user.is_staff:
        return HttpResponseForbidden()

    local = os.path.normpath(requested)
    return FileResponse(open(os.path.join(STATIC_ROOT, local.lstrip("/")), "rb"))
