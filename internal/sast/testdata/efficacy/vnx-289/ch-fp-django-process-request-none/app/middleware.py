from django.http import HttpResponseForbidden


class StaffOnlyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.path.lower().startswith("/staff/"):
            return self.get_response(request)
        if not request.user.is_staff:
            return HttpResponseForbidden()
        return self.get_response(request)
