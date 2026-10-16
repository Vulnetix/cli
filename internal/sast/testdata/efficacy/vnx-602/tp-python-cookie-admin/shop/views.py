from django.http import HttpResponse, HttpResponseForbidden


def admin_panel(request):
    # Reported by VNX-784 (a security decision on a cookie), not by this rule.
    if request.COOKIES.get('admin') == "1":
        return HttpResponse("welcome admin")
    return HttpResponseForbidden()


def promote(request):
    level = request.POST.get("user_role")
~>    if level == "admin":
        return HttpResponse("promoted")
    return HttpResponseForbidden()
