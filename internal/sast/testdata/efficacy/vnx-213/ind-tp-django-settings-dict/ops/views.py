from django.conf import settings
from django.http import JsonResponse


def debug_settings(request):
~>    return JsonResponse({k: repr(v) for k, v in vars(settings).items()})
