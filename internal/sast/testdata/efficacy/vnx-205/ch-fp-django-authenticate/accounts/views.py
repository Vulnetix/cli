from django.contrib.auth import authenticate, login
from django.shortcuts import redirect, render


def login_view(request):
    user = authenticate(request, username=request.POST["username"], password=request.POST["password"])
    if user is None:
        return render(request, "login.html", {"error": "Invalid credentials"})
    login(request, user)
    return redirect("home")
