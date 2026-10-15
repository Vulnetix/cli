from django.http import JsonResponse

from .models import User

ALLOWED = ("username", "email")


def register(request):
    user = User.objects.create(
        username=request.POST["username"],
        email=request.POST["email"],
    )
    return JsonResponse({"id": user.pk})


def register_filtered(request):
    clean = {k: request.POST[k] for k in ALLOWED if k in request.POST}
    user = User.objects.create(**clean)
    return JsonResponse({"id": user.pk})


def defaults_only(request):
    options = {"is_active": True}
    user = User.objects.create(username=request.POST["username"], **options)
    return JsonResponse({"id": user.pk})
