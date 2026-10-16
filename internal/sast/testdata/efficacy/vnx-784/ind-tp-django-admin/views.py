from django.http import HttpResponse


def dashboard(request):
~>    if request.COOKIES.get("admin") == "1":
        return HttpResponse("secret admin panel")
    return HttpResponse(status=403)
