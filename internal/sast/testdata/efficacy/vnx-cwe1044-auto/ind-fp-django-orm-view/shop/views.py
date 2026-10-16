from django.http import JsonResponse
from .models import Product


def cheap(request):
    items = Product.objects.filter(price__lt=10)
    # cursor.execute("SELECT 1") would belong in a repository
    sql = "SELECT * FROM product"  # only logged
    print("running", sql)
    return JsonResponse({"n": items.count()})
