import requests
from django.conf import settings
from django.http import HttpResponseForbidden


def signup(request):
    r = requests.post(
        "https://www.google.com/recaptcha/api/siteverify",
        data={"secret": settings.RECAPTCHA_SECRET, "response": request.POST["g-token"]},
        timeout=5,
    )
    result = r.json()
    if not result.get("success"):
        return HttpResponseForbidden()
    if result.get("score", 0.0) < settings.RECAPTCHA_MIN_SCORE:
        return HttpResponseForbidden()
    return create_account(request)
