from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme


def after_login(request):
    next_url = request.GET.get("next", "/")
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        next_url = "/"
    return HttpResponseRedirect(next_url)


def post_detail(request):
    post_id = request.GET.get("id")
    return redirect(f"/blog/{post_id}")


def section(request):
    return redirect("/docs/" + request.GET.get("page", "index"))


def named(request):
    return redirect("profile", username=request.user.username)
