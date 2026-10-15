from django.db import connection
from django.http import JsonResponse


def report(request):
~>    cursor = connection.cursor()
    cursor.execute("SELECT id, total FROM shop_order WHERE status = %s", ["paid"])
    rows = cursor.fetchall()
    return JsonResponse({"rows": rows})
