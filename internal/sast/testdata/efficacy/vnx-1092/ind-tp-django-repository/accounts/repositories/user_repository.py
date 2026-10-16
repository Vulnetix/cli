~>from django.http import HttpResponse
from django.db import connection


def search_users(request):
~>    term = request.GET.get("q", "")
    with connection.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE name = %s", [term])
        return cur.fetchone()
