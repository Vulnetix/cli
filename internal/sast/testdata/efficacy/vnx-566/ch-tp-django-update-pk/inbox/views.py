from django.db import connection
from django.http import JsonResponse


def mark_read(request, message_pk):
    with connection.cursor() as cursor:
        cursor.execute(
~>            "UPDATE inbox_message SET is_read = 1 WHERE id = %s",
            [message_pk],
        )
    return JsonResponse({"ok": True})
