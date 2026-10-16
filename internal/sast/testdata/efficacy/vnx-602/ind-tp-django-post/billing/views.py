from django.http import HttpResponseForbidden, JsonResponse
from django.views.decorators.http import require_POST

from .models import Invoice


@require_POST
def void_invoice(request, invoice_id):
~>    if request.POST.get("is_admin") == "1":
        Invoice.objects.filter(pk=invoice_id).update(status="void")
        return JsonResponse({"ok": True})
    return HttpResponseForbidden()
