from django.http import HttpResponseForbidden


class StaffOnlyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
~>        if request.path == "/admin/reports" and not request.user.is_staff:
            return HttpResponseForbidden()
        return self.get_response(request)


def before_request():
    path = request.path
~>    if path.startswith('/manage') and 'uid' not in session:
        abort(401)
