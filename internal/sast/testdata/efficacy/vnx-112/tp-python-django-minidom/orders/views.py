from xml.dom import minidom

import xmltodict
from django.http import JsonResponse


def submit(request):
~>    doc = minidom.parseString(request.body)
~>    data = xmltodict.parse(request.body.decode("utf-8"))
    return JsonResponse({"items": len(doc.childNodes), "keys": list(data)})
