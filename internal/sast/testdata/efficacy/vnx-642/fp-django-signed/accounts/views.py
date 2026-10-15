from django.http import HttpResponseForbidden


def login_view(request):
    resp = render(request, "home.html")
    resp.set_signed_cookie("role", user.role, salt="role")
    return resp


def admin_only(request):
    if request.get_signed_cookie("role", salt="role", default="") != "admin":
        return HttpResponseForbidden()
    return render(request, "admin.html")
