from django.core.exceptions import PermissionDenied


def delete_invoice(request, invoice_id):
    # assert request.user.is_staff  -- removed: stripped under python -O
    if not request.user.is_staff:
        raise PermissionDenied
    if not request.user.has_perm("billing.delete_invoice"):
        raise PermissionDenied("missing billing.delete_invoice")
    Invoice.objects.filter(pk=invoice_id).delete()
