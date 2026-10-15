from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme


def after_login(request):
    next_url = request.GET.get("next", "/")
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        next_url = "/"
    return redirect(next_url)
