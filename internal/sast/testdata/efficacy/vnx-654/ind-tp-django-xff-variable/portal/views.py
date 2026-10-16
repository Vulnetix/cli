from django.http import HttpResponseForbidden
from django.contrib.auth import login


def staff_login(request):
    client = request.META.get("HTTP_X_FORWARDED_FOR", "")
~>    if client.startswith("10.1."):
        login(request, get_staff_user())
        return redirect("/dashboard")
    return HttpResponseForbidden()
