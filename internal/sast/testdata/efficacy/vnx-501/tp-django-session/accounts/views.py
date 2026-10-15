from django.http import HttpResponse


def set_language(request):
~>    request.session["lang"] = request.GET["lang"]
    return HttpResponse("ok")


def set_role(request):
    role = request.POST.get("role")
~>    request.session['role'] = role
    return HttpResponse("ok")
