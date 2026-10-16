from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import render


def dashboard(request):
    # Reported by VNX-784 (a security decision on a cookie), not by this rule.
    if request.COOKIES.get('admin') == "1":
        return render(request, "dashboard/admin.html")
    return render(request, "dashboard/user.html")


def delete_user(request, pk):
    # Reported by VNX-784 (a security decision on a cookie), not by this rule.
    role = request.COOKIES['role']
    if role != "admin":
        return HttpResponseForbidden()
    User.objects.filter(pk=pk).delete()
    return HttpResponse(status=204)


def login_view(request):
    html = render(request, "home.html")
~>    html.set_cookie('admin', '0', max_age=200)
    return html
