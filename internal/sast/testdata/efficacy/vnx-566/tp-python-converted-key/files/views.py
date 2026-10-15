from django.db import connection
from django.http import HttpResponse


def remove_attachment(request):
    pk = int(request.POST["attachment"])
    with connection.cursor() as cursor:
~>        cursor.execute("DELETE FROM attachments WHERE id = %s" % pk)
    return HttpResponse(status=204)
