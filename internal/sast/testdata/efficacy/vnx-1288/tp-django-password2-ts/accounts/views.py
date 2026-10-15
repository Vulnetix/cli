from django.contrib.auth.models import User
from django.shortcuts import redirect


def signup(request):
    username = request.POST["username"]
    password1 = request.POST["password1"]
~>    password2 = request.POST.get("password2", "")
    User.objects.create_user(username=username, password=password1)
    return redirect("home")
