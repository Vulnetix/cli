from django.http import HttpResponseBadRequest
from django.shortcuts import redirect


def register(request):
    password = request.POST.get("password", "")
    password2 = request.POST.get("password2", "")
    if password2 != password:
        return HttpResponseBadRequest("Passwords do not match")
    create_user(request.POST["username"], password)
    return redirect("login")
