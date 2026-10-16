from django.http import HttpResponse, HttpResponseForbidden


def export_users(request):
    # A decision on a privilege cookie: VNX-784 reports it.
    if request.COOKIES.get("admin") == "yes":
        return HttpResponse(build_export())
    return HttpResponseForbidden()
