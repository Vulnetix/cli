from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.shortcuts import redirect, render


def login_view(request):
    if request.method == "POST":
        email = request.POST["email"]
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
~>            messages.error(request, "No account found with that email address.")
            return render(request, "login.html")
        if not user.check_password(request.POST["password"]):
            messages.error(request, "Wrong password.")
            return render(request, "login.html")
        login(request, user)
        return redirect("home")
    return render(request, "login.html")
