import csv

from django.http import StreamingHttpResponse

from .models import Contact


class Echo:
    def write(self, value):
        return value


def export_contacts(request):
    pseudo = Echo()
    out = csv.writer(pseudo)
    rows = Contact.objects.filter(owner=request.user).values_list("name", "company", "notes")
    response = StreamingHttpResponse(
~>        (out.writerow(row) for row in rows),
        content_type="text/csv",
    )
    response["Content-Disposition"] = 'attachment; filename="contacts.csv"'
    return response
