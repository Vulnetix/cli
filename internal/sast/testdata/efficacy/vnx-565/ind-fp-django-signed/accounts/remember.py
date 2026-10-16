from django.contrib.auth.models import User
from django.http import HttpResponse


def welcome(request):
    username = request.get_signed_cookie("username", salt="remember-me", default=None)
    user = User.objects.get(username=username)
    resp = HttpResponse("ok")
    resp.set_signed_cookie("user_id", str(user.id), salt="remember-me", max_age=86400)
    return resp
