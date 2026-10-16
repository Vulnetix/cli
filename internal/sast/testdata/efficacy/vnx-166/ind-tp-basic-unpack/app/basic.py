import base64

from django.http import HttpResponse


def basic_login(request):
    encoded = request.META.get("HTTP_AUTHORIZATION", "")[6:]
    decoded = base64.b64decode(encoded).decode("utf-8")
~>    username, password = decoded.split(":", 1)
    if not check_credentials(username, password):
        return HttpResponse(status=401)
    return HttpResponse("welcome")
