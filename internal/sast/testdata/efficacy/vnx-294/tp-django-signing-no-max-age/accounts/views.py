from django.core import signing
from django.core.signing import TimestampSigner


def activate(request, token):
~>    user_id = signing.loads(token, salt="activation")
    return activate_user(user_id)


def magic_link(request):
    value = request.GET["v"]
~>    username = TimestampSigner().unsign(value)
    return login_as(request, username)
