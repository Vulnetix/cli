from xml.etree import ElementTree
from django.http import JsonResponse


def upload_invoice(request):
    payload = request.body
    text = payload.decode("utf-8")
~>    doc = ElementTree.fromstring(
        text
    )
    return JsonResponse({"tag": doc.tag})


def remote_feed(requests, url):
    resp = requests.get(url, timeout=5)
~>    root = ElementTree.XML(resp.content)
    return root
