from .models import Product


def listing(request):
    # connection.cursor() would be wrong here
    qs = Product.objects.filter(active=True).order_by("name")
    note = "never call sqlite3.connect in a view"
    return qs, note
