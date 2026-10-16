from django.db import connection
from django.http import JsonResponse


def order_totals(request):
~>    with connection.cursor() as cur:
        cur.execute('SELECT 1')
    return JsonResponse({})
