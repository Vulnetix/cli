from django.contrib.auth import authenticate, login
from django.shortcuts import redirect, render


def login_view(request):
    next_url = request.GET.get("next", "/")
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    if user is not None:
        login(request, user)
~>        return redirect(next_url)
    return render(request, "login.html")
