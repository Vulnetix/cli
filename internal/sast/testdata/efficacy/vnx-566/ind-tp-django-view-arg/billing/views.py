from django.db import connection
from django.http import JsonResponse


def payment_method_detail(request, card_id):
    with connection.cursor() as cursor:
~>        cursor.execute("SELECT brand, last4, expiry FROM payment_methods WHERE card_id = %s", [card_id])
        row = cursor.fetchone()
    return JsonResponse({"brand": row[0], "last4": row[1], "expiry": row[2]})
