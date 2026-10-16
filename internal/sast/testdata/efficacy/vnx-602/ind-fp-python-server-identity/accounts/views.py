from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, JsonResponse


@login_required
def staff_only(request):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    if request.session.get("role") != "admin":
        return HttpResponseForbidden()
    return JsonResponse({"ok": True})
