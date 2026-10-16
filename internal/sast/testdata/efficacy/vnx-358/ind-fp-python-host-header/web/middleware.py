from django.core.exceptions import DisallowedHost

ALLOWED_SUFFIX = ".acme.com"


def match_host(request_host, allowed_suffix=ALLOWED_SUFFIX):
    host = request_host.split(":", 1)[0]
    return host == allowed_suffix.lstrip(".") or host.endswith(allowed_suffix)


class HostCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not match_host(request.get_host()):
            raise DisallowedHost(request.get_host())
        return self.get_response(request)
