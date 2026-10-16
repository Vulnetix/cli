from django.http import HttpResponse, HttpResponseForbidden


def admin_panel(request):
    if not request.user.is_authenticated:
        return HttpResponseForbidden()
    # Reported by VNX-784 (a security decision on a cookie), not by this rule.
    if request.COOKIES.get('admin') == "1":
        return HttpResponse("secret report")
    return HttpResponseForbidden()


def staff_page(request):
    # Reported by VNX-784 (a security decision on a cookie), not by this rule.
    staff = request.COOKIES["is_staff"] == "yes"
    if staff:
        return HttpResponse("staff tools")
    return HttpResponseForbidden()
