TRUSTED_PROXIES = {"10.0.0.5"}


def client_ip(request):
    remote = request.META.get("REMOTE_ADDR")
    if remote in TRUSTED_PROXIES:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
        if forwarded:
            return forwarded.split(",")[-1].strip()
    return remote


def last_hop(request):
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.rsplit(",", 1)[-1].strip()
    else:
        return request.remote_addr
