from django.http import HttpResponse, HttpResponseForbidden


def client_ip(request):
~>    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def internal_only(request):
    if client_ip(request) != "127.0.0.1":
        return HttpResponseForbidden()
    return HttpResponse("ok")
