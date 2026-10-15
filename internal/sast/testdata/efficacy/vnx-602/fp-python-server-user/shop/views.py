from django.http import HttpResponse, HttpResponseForbidden


def admin_panel(request):
    if request.user.is_authenticated and request.user.is_staff:
        return HttpResponse("welcome admin")
    if request.session.get("role") == "admin":
        return HttpResponse("ok")
    theme = request.COOKIES.get("theme")
    if theme == "dark":
        return HttpResponse("dark")
    return HttpResponseForbidden()
