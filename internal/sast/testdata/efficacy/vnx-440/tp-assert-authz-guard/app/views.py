from django.http import JsonResponse

from .models import Invoice


def delete_invoice(request, invoice_id):
~>    assert request.user.is_authenticated
~>    assert request.user.is_staff or request.user.has_perm("billing.delete_invoice"), "forbidden"
    Invoice.objects.filter(pk=invoice_id).delete()
    return JsonResponse({"ok": True})


def transfer(request, account):
~>    assert account.owner_id == request.user.id and can_transfer(request.user), \
        "not your account"
    return JsonResponse(account.transfer(request.POST["amount"]))
