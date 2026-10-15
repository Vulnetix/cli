from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect


@login_required
def password_change(request):
    if request.method == "POST":
~>        request.user.set_password(request.POST["new_password1"])
        request.user.save()
        return redirect("profile")
