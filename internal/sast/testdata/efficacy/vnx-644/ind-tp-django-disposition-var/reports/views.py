import csv

from django.http import HttpResponse


def export_csv(request):
    name = request.GET.get("name", "report")
    rows = build_rows(request.user)
    response = HttpResponse(content_type="text/csv")
~>    response["Content-Disposition"] = f'attachment; filename="{name}.csv"'
    writer = csv.writer(response)
    writer.writerows(rows)
    return response
