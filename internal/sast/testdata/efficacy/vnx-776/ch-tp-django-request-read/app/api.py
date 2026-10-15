from xml.etree import ElementTree


def soap_endpoint(request):
    raw = request.read()
~>    envelope = ElementTree.fromstring(raw)
    return envelope.find("Body")
