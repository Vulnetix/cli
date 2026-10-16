from django.http import HttpResponse

def login_done(request, user):
    resp = HttpResponse("ok")
    resp.set_signed_cookie("is_admin", "1" if user.is_staff else "0", salt="adm")
    resp.set_cookie("theme", "dark")
    request.session["role"] = user.role
    return resp

def whoami(request):
    flag = request.get_signed_cookie("is_admin", default="0", salt="adm")
    return HttpResponse(flag)
