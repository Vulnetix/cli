from django.db import connection
from django.http import JsonResponse


def top_questions(request):
~>    with connection.cursor() as cur:
~>        cur.execute(
            "SELECT id, text FROM polls_question ORDER BY votes DESC LIMIT 5"
        )
        rows = cur.fetchall()
    return JsonResponse({"rows": rows})
