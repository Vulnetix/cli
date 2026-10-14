from django.http import JsonResponse

from catalog.models import Item


def search(request):
    term = request.GET.get("q", "")
~>    items = Item.objects.raw("SELECT * FROM catalog_item WHERE name LIKE %s", [term])
    return JsonResponse({"items": [i.name for i in items]})
