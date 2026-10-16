from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.utils.cache import patch_cache_control
from django.views.decorators.cache import cache_control, never_cache


@login_required
@never_cache
def invoice_list(request):
    return render(request, "billing/invoices.html", {"user": request.user})


@login_required
@cache_control(private=True, no_cache=True)
def statement(request, pk):
    return render(request, "billing/statement.html", {"statement": pk})


@login_required
def export_csv(request):
    response = render(request, "billing/export.csv", {"rows": []})
    response["Cache-Control"] = "private, max-age=60"
    return response


@login_required
def profile(request):
    response = render(request, "accounts/profile.html", {"user": request.user})
    patch_cache_control(response, no_store=True)
    return response
