from django.http import JsonResponse
from django.views.decorators.http import require_POST


@require_POST
def delete_invoice(request, invoice_id):
~>    assert request.user.is_authenticated
    invoice = Invoice.objects.get(pk=invoice_id)
~>    assert request.user.has_perm("billing.delete_invoice") or invoice.owner_id == request.user.id
    invoice.delete()
    return JsonResponse({"deleted": invoice_id})
