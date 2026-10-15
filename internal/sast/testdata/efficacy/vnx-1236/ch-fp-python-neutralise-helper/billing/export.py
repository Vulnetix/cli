import csv

from django.http import HttpResponse

DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def _cell(value):
    text = "" if value is None else str(value)
    if text.startswith(DANGEROUS):
        return "'" + text
    return text


def invoices_csv(request):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="invoices.csv"'
    writer = csv.writer(response)
    writer.writerow(["Number", "Customer", "Memo"])
    for inv in request.user.invoices.all():
        writer.writerow([_cell(inv.number), _cell(inv.customer_name), _cell(inv.memo)])
    return response
