from django.db import connection
from django.http import JsonResponse


def document_detail(request, doc_id):
    with connection.cursor() as cursor:
~>        cursor.execute("SELECT title, body FROM documents WHERE id = %s", [doc_id])
        row = cursor.fetchone()
    return JsonResponse({"title": row[0], "body": row[1]})
