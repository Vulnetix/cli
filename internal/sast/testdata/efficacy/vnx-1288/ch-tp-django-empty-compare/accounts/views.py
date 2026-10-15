from django.shortcuts import render, redirect
from django.contrib.auth.models import User


def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        password1 = request.POST["password1"]
~>        password2 = request.POST["password2"]
        if password2 == "":
            return render(request, "register.html", {"error": "confirm your password"})
        User.objects.create_user(username=username, password=password1)
        return redirect("login")
    return render(request, "register.html")
