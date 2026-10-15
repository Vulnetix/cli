from django.http import HttpResponseRedirect
from django.shortcuts import render


def settings_page(request):
    if not request.user.is_authenticated:
~>        HttpResponseRedirect("/accounts/login/")
    profile = request.user.profile
    return render(request, "settings.html", {"profile": profile})
