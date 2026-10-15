from django.core.cache import cache


def start_signup(request):
    password = request.POST["password"]
~>    cache.set(f"signup:{request.session.session_key}", password, timeout=600)


def remember(request, redis_client):
~>    redis_client.setex("pending:" + request.POST["email"], 300, request.POST.get("password"))
