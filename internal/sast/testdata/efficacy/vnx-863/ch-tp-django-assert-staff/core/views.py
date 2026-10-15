from django.http import JsonResponse


def wipe_cache(request):
~>    assert request.user.is_staff, "staff only"
    cache.clear()
    return JsonResponse({"ok": True})
