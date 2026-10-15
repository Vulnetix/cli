from django.http import HttpResponseForbidden


class OriginCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        origin = request.META.get("HTTP_ORIGIN", "")
~>        if request.method == "POST" and not origin.endswith("example.com"):
            return HttpResponseForbidden()
        return self.get_response(request)
