from django.db import connection
from django.http import JsonResponse

def report(request):
    with connection.cursor() as cur:
~>        cur.execute("SELECT id, total FROM orders WHERE user_id = %s", [request.user.id])
        rows = cur.fetchall()
    return JsonResponse({"rows": rows})
