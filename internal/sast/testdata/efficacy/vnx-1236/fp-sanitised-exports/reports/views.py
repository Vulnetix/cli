import csv

from django.http import HttpResponse

from .models import Customer

FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _cell(value):
    text = str(value)
    if text.startswith(FORMULA_START):
        return "'" + text
    return text


def export_customers(request):
    response = HttpResponse(content_type="text/csv")
    writer = csv.writer(response)
    for c in Customer.objects.all():
        writer.writerow([_cell(c.name), _cell(c.notes)])
    return response
