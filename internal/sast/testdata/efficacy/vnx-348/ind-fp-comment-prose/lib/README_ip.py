"""Client address helpers.

Older code read X-Forwarded-For and fell back to REMOTE_ADDR; that let any
client choose its address, so we only trust the socket now.
"""


def client_ip(request):
    # was: request.META.get("HTTP_X_FORWARDED_FOR") or request.META.get("REMOTE_ADDR")
    return request.META.get("REMOTE_ADDR")
