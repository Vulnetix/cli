import requests
from django.conf import settings
from django.http import HttpResponseForbidden

VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


def signup(request):
    r = requests.post(
        VERIFY_URL,
        data={"secret": settings.RECAPTCHA_SECRET, "response": request.POST["g-token"]},
        timeout=5,
    )
~>    if not r.json().get("success"):
        return HttpResponseForbidden()
    return create_account(request)
