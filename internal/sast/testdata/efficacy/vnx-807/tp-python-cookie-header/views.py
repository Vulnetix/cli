from django.http import HttpResponse


def admin_panel(request):
~>    if request.COOKIES.get('admin') == "1":
        return HttpResponse("welcome admin")
    cookie = request.COOKIES.get("session_info", "")
~>    if cookie.split("|")[0] == "admin":
        return HttpResponse("welcome admin")
    return HttpResponse(status=403)
