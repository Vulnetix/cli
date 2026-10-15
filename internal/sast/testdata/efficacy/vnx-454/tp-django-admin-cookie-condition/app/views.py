from django.http import HttpResponse, HttpResponseForbidden


def admin_panel(request):
    if not request.user.is_authenticated:
        return HttpResponseForbidden()
~>    if request.COOKIES.get('admin') == "1":
        return HttpResponse("secret report")
    return HttpResponseForbidden()


def staff_page(request):
~>    staff = request.COOKIES["is_staff"] == "yes"
    if staff:
        return HttpResponse("staff tools")
    return HttpResponseForbidden()
