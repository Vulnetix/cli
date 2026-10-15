from django.http import HttpResponse, HttpResponseForbidden

from .models import Account


def api_login(request):
    account = Account.objects.get(username=request.POST.get("username"))
~>    if account.password_hash == request.POST.get("password_hash"):
        request.session["uid"] = account.id
        return HttpResponse("ok")
    return HttpResponseForbidden()
