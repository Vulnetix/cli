from django.http import HttpResponseForbidden
from flask import request as flask_request


def admin_panel(request):
~>    if request.COOKIES.get("admin") == "1":
        return render_admin(request)
    return HttpResponseForbidden()


def staff_only(request):
~>    role = request.COOKIES["role"]
    if role != "staff":
        return HttpResponseForbidden()
    return render_staff(request)


def flask_dashboard():
~>    if flask_request.cookies.get('is_admin'):
        return dashboard()
    return "denied", 403
