from django.contrib.auth.hashers import check_password
from django.http import HttpResponse

from .models import Member


def login_view(request):
    try:
        member = Member.objects.get(username=request.POST["username"])
    except Member.DoesNotExist:
        member = None
~>    if not member:
        return HttpResponse(status=401)

    if not check_password(request.POST["password"], member.password):
        return HttpResponse(status=401)
    return HttpResponse("ok")
