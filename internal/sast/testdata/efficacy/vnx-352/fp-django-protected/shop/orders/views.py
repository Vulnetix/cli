from django.views.decorators.csrf import csrf_exempt, csrf_protect, ensure_csrf_cookie
from django.http import JsonResponse

HELP = "Never decorate a state-changing view with @csrf_exempt"


@csrf_protect
def cancel_order(request, order_id):
    return JsonResponse({"ok": True})


@ensure_csrf_cookie
def page(request):
    return JsonResponse({"csrf_exempt": False})


def is_csrf_exempt(view):
    return getattr(view, "csrf_exempt", False)
