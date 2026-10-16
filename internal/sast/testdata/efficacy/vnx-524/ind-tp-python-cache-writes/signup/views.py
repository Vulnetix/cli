import secrets

import redis
from django.core.cache import cache
from django.http import JsonResponse

redis_client = redis.Redis(host="cache", port=6379)


def start_signup(request):
    key = secrets.token_urlsafe(16)
    password = request.POST["password"]
~>    cache.set(f"signup:{key}", password, timeout=600)
    return JsonResponse({"next": f"/signup/verify/{key}"})


def stash_reset(request):
    token = secrets.token_urlsafe(24)
~>    redis_client.setex(f"reset:{token}", 900, request.POST.get("new_password"))
    return JsonResponse({"ok": True})
