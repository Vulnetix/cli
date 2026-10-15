import os

from django.http import JsonResponse

PUBLIC = ("APP_VERSION", "REGION")


def info(request):
    return JsonResponse({k: v for k, v in os.environ.items() if k in PUBLIC})


def build(request):
    return JsonResponse({k: v for k, v in os.environ.items() if k.startswith("BUILD_")})
