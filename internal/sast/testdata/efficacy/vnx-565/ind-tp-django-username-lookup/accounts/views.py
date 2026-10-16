from django.contrib.auth.models import User
from django.shortcuts import redirect, render


def dashboard(request):
~>    user = User.objects.get(username=request.COOKIES.get("username"))
    if user is None:
        return redirect("login")
    return render(request, "dashboard.html", {"user": user})
