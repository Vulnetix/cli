from django.db import connection
from django.http import JsonResponse

from .models import Account


def login(request):
    name = request.POST.get("name")
    password = request.POST.get("pass")
    sql_query = "SELECT * FROM shop_account WHERE user='" + name + "' AND password='" + password + "'"
    print(sql_query)
~>    rows = Account.objects.raw(sql_query)
    return JsonResponse({"ok": bool(list(rows))})


def search(request):
    term = request.GET["q"]
    sql = f'SELECT title FROM shop_post WHERE title LIKE \'%{term}%\''
    with connection.cursor() as cursor:
~>        cursor.execute(sql)
        order = request.GET.get("order", "id")
        query = "SELECT * FROM shop_post ORDER BY "
        query += order
~>        cursor.execute(query)
        stmt = "SELECT * FROM shop_post WHERE author = '%s'" % request.user.username
~>        cursor.execute(stmt)
        return JsonResponse({"rows": cursor.fetchall()})
