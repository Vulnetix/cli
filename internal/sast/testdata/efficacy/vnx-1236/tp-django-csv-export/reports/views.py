import csv

from django.http import HttpResponse

from .models import Customer


def export_customers(request):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="customers.csv"'
    writer = csv.writer(response)
    writer.writerow(["Name", "Email", "Notes"])
    for c in Customer.objects.all():
~>        writer.writerow([c.name, c.email, c.notes])
    return response


def export_rows(request):
    response = HttpResponse(content_type="text/csv")
    out = csv.writer(response, delimiter=";")
~>    out.writerows(Customer.objects.values_list("name", "notes"))
    return response
