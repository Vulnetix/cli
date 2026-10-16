from django.core.exceptions import PermissionDenied
from django.http import JsonResponse

from .models import Invoice


def mine(request):
    inv = Invoice.objects.get(id=request.GET["invoice_id"], user=request.user)
    return JsonResponse({"total": inv.total})


def checked(request, pk):
    doc = Invoice.objects.get(pk=pk)
    if doc.owner_id != request.user.id:
        raise PermissionDenied
    return JsonResponse({"total": doc.total})
