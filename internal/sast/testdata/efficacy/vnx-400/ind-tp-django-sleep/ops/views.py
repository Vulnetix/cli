import time

from django.http import JsonResponse


def simulate_latency(request):
    delay = float(request.GET.get("delay", "0"))
~>    time.sleep(delay)
    return JsonResponse({"slept": delay})
