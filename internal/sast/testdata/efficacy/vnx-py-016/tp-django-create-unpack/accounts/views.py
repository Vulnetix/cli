from django.http import JsonResponse
from django.views.decorators.http import require_POST

from .models import Profile, User


@require_POST
def register(request):
~>    user = User.objects.create(**request.POST.dict())
    return JsonResponse({"id": user.pk})


def api_register(request):
~>    user = User.objects.create( ** request.data)
    return JsonResponse({"id": user.pk})


def save_profile(request):
~>    profile, _ = Profile.objects.update_or_create(user=request.user, **request.data)
    return JsonResponse({"id": profile.pk})
