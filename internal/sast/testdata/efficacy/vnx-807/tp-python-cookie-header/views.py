from django.http import HttpResponse


def admin_panel(request):
    # Reported by VNX-784 (a security decision on a cookie), not by this rule.
    if request.COOKIES.get('admin') == "1":
        return HttpResponse("welcome admin")
    cookie = request.COOKIES.get("session_info", "")
~>    if cookie.split("|")[0] == "admin":
        return HttpResponse("welcome admin")
    return HttpResponse(status=403)
