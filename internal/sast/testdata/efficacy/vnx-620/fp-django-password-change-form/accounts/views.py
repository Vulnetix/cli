from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm


def change_password(request):
    form = PasswordChangeForm(request.user, request.POST)
    if form.is_valid():
        user = form.save()
        update_session_auth_hash(request, user)
        return redirect("profile")
