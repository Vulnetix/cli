from .models import Product


def chunks(seq, size):
    for start in range(0, len(seq), size):
        yield seq[start:start + size]


def refresh(cursor, ids):
    for batch in chunks(ids, 500):
        cursor.execute("UPDATE product SET synced = 1 WHERE id IN %s", (tuple(batch),))


def fetch(ids):
    found = []
    for group in chunks(ids, 1000):
        found.extend(Product.objects.filter(pk__in=group))
    return found
