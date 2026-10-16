from django.db import connection


def global_settings(request):
    # Previously: cursor.execute("SELECT * FROM settings WHERE id = %s", [request.GET["id"]])
    with connection.cursor() as cursor:
        cursor.execute("SELECT theme, locale FROM settings WHERE id = 1")
        return cursor.fetchone()
