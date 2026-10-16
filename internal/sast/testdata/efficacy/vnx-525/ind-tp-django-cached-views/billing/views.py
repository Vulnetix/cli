from django.contrib.auth.decorators import login_required, permission_required
from django.shortcuts import render
from django.views.decorators.cache import cache_control, cache_page

from billing.models import Invoice


@login_required
~>@cache_page(60 * 15)
def invoice_list(request):
    invoices = Invoice.objects.filter(customer=request.user.customer)
    return render(request, "billing/invoices.html", {"invoices": invoices})


@permission_required("billing.view_statement")
~>@cache_control(public=True, max_age=3600)
def statement(request, pk):
    return render(request, "billing/statement.html", {"statement": pk})


@login_required
def export_csv(request):
    response = render(request, "billing/export.csv", {"rows": []})
~>    response["Cache-Control"] = "public, max-age=86400"
    return response
