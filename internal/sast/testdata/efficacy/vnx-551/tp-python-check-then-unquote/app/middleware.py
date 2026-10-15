from urllib.parse import unquote

from django.http import HttpResponseForbidden


class AdminGate:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        raw = request.get_full_path()
~>        if raw.startswith("/admin") and not request.user.is_staff:
            return HttpResponseForbidden()
        request.resource = unquote(raw)
        return self.get_response(request)
