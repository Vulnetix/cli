from django.http import JsonResponse

from shop.models import Product


def product_count(request):
    count = Product.objects.filter(active=True).count()
    connection_count = request.session.get("connections", 0)
    cursor_position = int(request.GET.get("cursor", 0))
    return JsonResponse({"count": count, "cursor": cursor_position, "c": connection_count})
