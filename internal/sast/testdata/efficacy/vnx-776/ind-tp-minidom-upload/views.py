from xml.dom import minidom
from django.http import HttpResponse


def upload(request):
    data = request.body
~>    dom = minidom.parseString(data)
    names = [n.firstChild.data for n in dom.getElementsByTagName("name")]
    return HttpResponse(",".join(names))
