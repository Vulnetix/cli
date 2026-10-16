import sqlite3

from django.db import connection
from django.http import JsonResponse

from library.models import Book


def overdue(request):
    conn = sqlite3.connect("/var/lib/library/loans.db")
    rows = conn.execute("SELECT id FROM loans WHERE due < date('now')").fetchall()
    return JsonResponse({"ids": [r[0] for r in rows]})


def by_author(request, author_id):
    books = Book.objects.raw("SELECT * FROM library_book WHERE author_id = %s", [author_id])
    return JsonResponse({"titles": [b.title for b in books]})


def shelf_counts(request):
    with connection.cursor() as cur:
        cur.execute("SELECT shelf, COUNT(*) FROM library_book GROUP BY shelf")
        return JsonResponse(dict(cur.fetchall()))
