import hmac
from django.http import HttpResponseBadRequest


def register(request):
    p1 = request.POST.get("password1")
    p2 = request.POST.get("password2")
    if not (p1 and p1 == p2):
        return HttpResponseBadRequest("mismatch")
    return create(request, p1)


def reset(request):
    new = request.form["password"]
    again = request.form["confirm_password"]
    if not hmac.compare_digest(new, again):
        return "no", 400
    return "ok"
