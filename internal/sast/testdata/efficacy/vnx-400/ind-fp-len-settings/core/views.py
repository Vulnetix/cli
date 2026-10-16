import time

from django.conf import settings
from django.http import JsonResponse


def echo_lengths(request):
    body = request.POST.get("text", "")
    stars = "*" * len(body)
    time.sleep(settings.ECHO_DELAY_SECONDS)
    for _ in range(10):
        pass
    return JsonResponse({"masked": stars})
