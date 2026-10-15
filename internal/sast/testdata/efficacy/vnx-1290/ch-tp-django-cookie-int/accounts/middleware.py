import base64

from django.contrib.auth.models import User


class RememberMeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        raw = request.COOKIES.get("remember_user")
        if raw:
~>            user_id = int(base64.b64decode(raw))
            request.user = User.objects.get(pk=user_id)
        return self.get_response(request)
