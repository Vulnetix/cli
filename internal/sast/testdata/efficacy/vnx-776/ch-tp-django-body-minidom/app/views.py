from xml.dom.minidom import parseString
from django.http import JsonResponse


def import_feed(request):
    payload = request.body
~>    doc = parseString(payload)
    items = doc.getElementsByTagName("item")
    return JsonResponse({"count": len(items)})
