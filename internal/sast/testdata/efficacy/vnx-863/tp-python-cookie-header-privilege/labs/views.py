from django.shortcuts import render
from flask import request as flask_request


def secret_page(request):
~>    if request.COOKIES.get('admin') == "1":
        return render(request, "secret.html", {"flag": "ADMIN"})
    return render(request, "secret.html", {})


def session_lab(request):
    cookie = request.COOKIES["cookie"]
    if cookie.split('|')[1] == "expired":
        return render(request, "expired.html")
~>    elif cookie.split('|')[0] == 'admin':
        return render(request, "admin.html")
    return render(request, "user.html")


def report():
~>    if flask_request.headers.get("X-User-Role") == "admin":
        return "all reports"
    return "your reports"


def legacy(request):
~>    if request.META.get("HTTP_X_IS_STAFF"):
        return render(request, "staff.html")
    return render(request, "home.html")
