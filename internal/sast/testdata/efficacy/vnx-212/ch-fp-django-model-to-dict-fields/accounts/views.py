from django.forms.models import model_to_dict
from django.http import JsonResponse


def me(request):
    return JsonResponse(model_to_dict(request.user, fields=["id", "username", "email"]))


def order(request, order):
    return JsonResponse(model_to_dict(order))
