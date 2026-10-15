from django.shortcuts import redirect, render

from .forms import SignupForm
from .models import Account


def signup(request):
    form = SignupForm(request.POST)
    if form.is_valid():
        Account.objects.create(**form.cleaned_data)
        return redirect("home")
    return render(request, "signup.html", {"form": form})
