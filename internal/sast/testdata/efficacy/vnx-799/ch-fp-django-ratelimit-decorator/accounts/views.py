from django.contrib.auth import authenticate, login
from django.shortcuts import redirect, render
from django_ratelimit.decorators import ratelimit


@ratelimit(key="ip", rate="5/m", method="POST", block=True)
@ratelimit(key="post:username", rate="5/m", method="POST", block=True)
def login_view(request):
    if request.method == "POST":
        user = authenticate(request, username=request.POST["username"], password=request.POST["password"])
        if user is not None:
            login(request, user)
            return redirect("profile")
    return render(request, "accounts/login.html")


def profile(request):
    return render(request, "accounts/profile.html")
