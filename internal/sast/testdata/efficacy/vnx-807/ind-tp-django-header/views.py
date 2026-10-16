from django.http import HttpResponse


def panel(request):
~>    if request.headers.get("X-Authenticated") == "true":
        return HttpResponse("welcome admin")
    return HttpResponse(status=403)
