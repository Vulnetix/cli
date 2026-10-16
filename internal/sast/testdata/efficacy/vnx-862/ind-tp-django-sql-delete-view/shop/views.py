from django.db import connection
from django.http import HttpResponse


~>def purge_orders(request, customer_id):
    with connection.cursor() as cur:
        cur.execute("DELETE FROM orders WHERE customer_id = %s", [customer_id])
    return HttpResponse("purged")
