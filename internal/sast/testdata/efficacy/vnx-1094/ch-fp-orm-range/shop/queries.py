from shop.models import Order


def recent(start, end):
    return list(Order.objects.filter(created__gte=start, created__lt=end))


def ids(cur, start):
    cur.execute("SELECT max(id) FROM orders WHERE created_at > %s", (start,))
    return cur.fetchall()
