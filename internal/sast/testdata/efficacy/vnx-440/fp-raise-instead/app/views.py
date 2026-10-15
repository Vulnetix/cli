from django.core.exceptions import PermissionDenied

# assert request.user.is_staff  -- removed: stripped by python -O


def delete_invoice(request, invoice_id):
    if not request.user.is_staff:
        raise PermissionDenied
    if invoice_id is None:
        raise AssertionError("unreachable")
    doc = "assert request.user.is_authenticated is unsafe"
    return doc
