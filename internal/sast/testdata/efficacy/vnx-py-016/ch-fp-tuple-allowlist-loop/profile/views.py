from django.http import JsonResponse
from django.utils import timezone

from .models import Profile


def update(request, pk):
    profile = Profile.objects.get(pk=pk, owner=request.user)
    for field in ("display_name", "bio", "website"):
        if field in request.POST:
            setattr(profile, field, request.POST[field])
    setattr(profile, "updated_at", timezone.now())
    profile.save()
    return JsonResponse({"ok": True})
