from django.contrib.auth import authenticate

MAX_ATTEMPTS = 3


def login_view(request):
    user = User.objects.get(username=request.POST["username"])
    if not user.check_password(request.POST["password"]):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_ATTEMPTS:
~>            user.is_locked = True
        user.save()
        return render(request, "login.html", {"error": "invalid"})
    user.failed_attempts = 0
    user.save()
    return redirect("home")
