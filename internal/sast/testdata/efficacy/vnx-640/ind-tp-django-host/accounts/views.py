import secrets

from django.core.mail import send_mail
from django.http import HttpResponse

from .models import PasswordReset


def forgot_password(request):
    token = secrets.token_urlsafe(32)
    PasswordReset.objects.create(email=request.POST["email"], token=token)
~>    reset_link = "https://" + request.META["HTTP_HOST"] + "/reset/" + token
    send_mail("Password reset", reset_link, None, [request.POST["email"]])
    return HttpResponse(status=204)
