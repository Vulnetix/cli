import sqlite3 as sq
from sqlite3 import connect

from django.http import JsonResponse


def stock(request):
~>    db = sq.connect("/var/lib/shop/stock.db")
    rows = db.execute("SELECT sku, qty FROM stock").fetchall()
    return JsonResponse({"stock": rows})


def prices(request):
~>    db = connect("/var/lib/shop/stock.db")
    return JsonResponse({"prices": db.execute("SELECT * FROM prices").fetchall()})
