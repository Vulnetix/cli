from django.http import HttpResponsePermanentRedirect, HttpResponseRedirect
from django.shortcuts import redirect


def after_login(request):
    next_url = request.GET.get("next")
~>    return HttpResponseRedirect(next_url)


def moved(request):
~>    return HttpResponsePermanentRedirect(request.POST["location"])


def bounce(request):
~>    return redirect(f"{request.GET['r']}")
