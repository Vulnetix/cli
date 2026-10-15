from django.http import JsonResponse
from django.views.decorators.http import require_POST

from .models import Account


@require_POST
def edit(request, pk):
~>    Account.objects.filter(pk=pk).update(**request.POST.dict())
    return JsonResponse({"ok": True})
