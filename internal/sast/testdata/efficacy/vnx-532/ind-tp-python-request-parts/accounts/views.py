import logging

from django.contrib.auth import authenticate, login
from django.http import JsonResponse

logger = logging.getLogger(__name__)


def login_view(request):
~>    logger.info("login attempt: %s", request.POST)
    user = authenticate(request, username=request.POST.get("username"), password=request.POST.get("password"))
    if user is None:
~>        logger.warning("failed login from %s headers=%s",
                       request.META.get("REMOTE_ADDR"),
                       request.headers)
        return JsonResponse({"ok": False}, status=401)
    login(request, user)
    return JsonResponse({"ok": True})


def webhook(request):
~>    print("webhook body:", request.body)
~>    logger.debug("auth header %s", request.headers["Authorization"])
    return JsonResponse({"received": True})
