from django.http import HttpResponse, HttpResponseForbidden


def lab_login(request):
~>    obj = Account.objects.filter(userid=request.COOKIES['userid'])[0]
    return HttpResponse(obj.name)


def admin_panel(request):
~>    if request.COOKIES.get('admin') == "1":
        return HttpResponse("welcome admin")
    return HttpResponseForbidden()


def remember(request, obj):
    response = HttpResponse("ok")
~>    response.set_cookie('userid', obj.userid, max_age=3600)
    return response
