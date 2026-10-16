from django.db import connection


def clean_term(q):
~>    return q.replace("UNION", "").replace(" ", "")


def search(request):
    term = clean_term(request.GET.get("q", ""))
    with connection.cursor() as cur:
        cur.execute("SELECT id, name FROM products WHERE name LIKE '%" + term + "%'")
        return cur.fetchall()
