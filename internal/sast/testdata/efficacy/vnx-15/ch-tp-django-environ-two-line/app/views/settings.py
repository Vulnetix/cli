import os
from django.http import JsonResponse


def set_timezone(request):
    tz = request.POST.get("tz", "UTC")
    # apply for the rest of the worker's life
~>    os.environ["TZ"] = tz
    return JsonResponse({"ok": True})


def set_locale(request):
~>    os.putenv("LANG", request.GET["lang"])
    return JsonResponse({"ok": True})
