from django.http import JsonResponse

DEBUG_TOOLBAR = False


def update_settings(request):
    for key, value in request.POST.items():
~>        globals()[key] = value
    return JsonResponse({"ok": True})


def bulk(request):
~>    globals().update(request.GET.dict())
    return JsonResponse({"ok": True})


def scoped(request):
    payload = request.json
~>    vars(settings_module).update(payload)
    return JsonResponse({"ok": True})
