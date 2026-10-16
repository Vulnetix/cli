import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import Subscription


~>@csrf_exempt
@login_required
@require_POST
def change_plan(request):
    payload = json.loads(request.body)
    sub = Subscription.objects.get(owner=request.user, pk=payload["id"])
    sub.plan = payload["plan"]
    sub.save(update_fields=["plan"])
    return JsonResponse({"ok": True, "plan": sub.plan})
