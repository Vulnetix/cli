from django.http import JsonResponse

from .models import Invoice


def invoice_detail(request):
    invoice_id = request.GET["invoice_id"]
~>    inv = Invoice.objects.get(id=invoice_id)
    return JsonResponse({"total": inv.total})
