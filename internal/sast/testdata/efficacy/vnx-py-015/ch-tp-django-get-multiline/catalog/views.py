import re

from django.http import JsonResponse

from .models import Product


def search(request):
    names = Product.objects.values_list("name", flat=True)
    matches = [
        n for n in names
~>        if re.search(
            request.GET.get("q", ""),
            n,
            re.IGNORECASE,
        )
    ]
    return JsonResponse({"matches": matches})
