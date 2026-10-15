import os

from django.http import JsonResponse


def debug_env(request):
~>    return JsonResponse({key: value for key, value in os.environ.items()})
