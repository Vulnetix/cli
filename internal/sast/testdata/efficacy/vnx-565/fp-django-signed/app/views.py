from django.http import HttpResponse
from itsdangerous import URLSafeSerializer

signer = URLSafeSerializer("key")


def view(request):
    uid = request.get_signed_cookie("userid", salt="auth")
    account = Account.objects.get(pk=uid)
    data = signer.loads(request.COOKIES.get("user"))
    if data["role"] == "admin":
        return HttpResponse("admin")
    return HttpResponse(account.name)


def remember(request, user):
    response = HttpResponse("ok")
    response.set_signed_cookie("userid", user.id, salt="auth")
    response.set_cookie("theme", "dark")
    return response
