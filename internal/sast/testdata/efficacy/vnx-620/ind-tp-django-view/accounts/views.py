from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render


@login_required
def change_password(request):
    if request.method == "POST":
        new_password = request.POST["new_password"]
        confirm = request.POST["confirm_password"]
        if new_password != confirm:
            return render(request, "accounts/change_password.html", {"error": "Passwords differ"})
~>        request.user.set_password(new_password)
        request.user.save()
        update_session_auth_hash(request, request.user)
        return redirect("profile")
    return render(request, "accounts/change_password.html")
