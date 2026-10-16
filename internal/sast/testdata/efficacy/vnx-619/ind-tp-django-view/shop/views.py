from django.db import connection
from django.http import JsonResponse


def stock_report(request):
~>    cursor = connection.cursor()
    cursor.execute("SELECT sku, qty FROM inventory WHERE qty < %s", [10])
    low = cursor.fetchall()
    return JsonResponse({"low": low})
