from django.http import JsonResponse
from lxml import etree


def upload(request):
    payload = request.body
~>    root = etree.fromstring(payload)
    return JsonResponse({"tag": root.tag})
