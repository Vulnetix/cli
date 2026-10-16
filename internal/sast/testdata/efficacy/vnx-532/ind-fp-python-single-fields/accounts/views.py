import logging

from django.shortcuts import render

logger = logging.getLogger(__name__)


def login_view(request):
    logger.info("login attempt path=%s ua=%s", request.path, request.headers.get("User-Agent"))
    logger.info("request id %s", request.headers.get("X-Request-Id"))
    logger.debug("body size %d", len(request.body))
    logger.debug("form keys %s", list(request.POST.keys()))
    if "Authorization" in request.headers:
        logger.info("bearer auth used")
    # logger.info("login attempt: %s", request.POST)
    return render(request, "login.html", {"form": request.POST, "cookies": request.COOKIES})
