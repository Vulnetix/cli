from django.http import HttpResponse, HttpResponseForbidden


def internal_status(request):
    ip = request.META.get("REMOTE_ADDR")
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
~>    if ip == "127.0.0.1":
        return HttpResponse(render_status())
    return HttpResponseForbidden()
