from django.http import HttpResponseRedirect
from django.shortcuts import redirect


def after_login(request):
    next_url = request.GET.get("next", "/")
    if next_url.endswith("acme.example.com"):
~>        return HttpResponseRedirect(next_url)
    return redirect("/")


def sso_return(request):
    target = request.GET["target"]
    if target.startswith('https://sso.acme.example.com'):
~>        return redirect( target )
    return redirect("/")
