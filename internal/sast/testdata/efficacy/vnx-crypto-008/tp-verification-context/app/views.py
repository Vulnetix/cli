import hashlib

from django.conf import settings
from django.http import HttpResponseForbidden


def reset_password(request):
    token = request.POST.get("token")
~>    if token != settings.reset_token:
        return HttpResponseForbidden()


class TokenAuth:
    def authenticate(self, token):
~>        return token == self.secret_token


def accept_upload(body, stored_digest):
    digest = hashlib.sha256(body).hexdigest()
~>    return digest == stored_digest


def unsubscribe(submitted_token, account):
~>    return submitted_token == account.unsubscribe_token
