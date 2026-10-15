from django.core import signing
from django.shortcuts import get_object_or_404, redirect, render

from .models import Invitation


def accept_invitation(request, key):
    invitation = get_object_or_404(Invitation, key=signing.loads(key, max_age=86400))
    if request.method == "POST":
        new_password = request.POST["new_password"]
        user = invitation.user
        user.set_password(new_password)
        user.save()
        invitation.delete()
        return redirect("login")
    return render(request, "accounts/accept.html", {"invitation": invitation})
