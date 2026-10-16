from django.http import JsonResponse
from django.views.decorators.http import require_POST

from .models import SiteConfig


@require_POST
def patch_config(request):
    config = SiteConfig.objects.first()
~>    config.__dict__.update(request.POST.dict())
    config.save()
    return JsonResponse({"ok": True})
