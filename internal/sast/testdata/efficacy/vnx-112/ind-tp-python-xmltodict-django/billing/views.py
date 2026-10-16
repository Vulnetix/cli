import xmltodict
from xml.dom import minidom

from django.http import HttpResponse
from django.views.decorators.http import require_POST


@require_POST
def payment_notification(request):
~>    data = xmltodict.parse(request.body)
    amount = data["notification"]["amount"]
    Payment.objects.create(amount=amount)
    return HttpResponse(status=204)


@require_POST
def refund(request):
~>    doc = minidom.parseString(request.body)
    ref = doc.getElementsByTagName("ref")[0].firstChild.data
    return HttpResponse(ref)
