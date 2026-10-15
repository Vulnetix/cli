def client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded in (None, "", "unknown"):
        return request.META.get("REMOTE_ADDR")
    if request.headers.get("X-Real-IP") in (None, ""):
        return forwarded.split(",")[0].strip()
    return request.headers.get("X-Real-IP")
