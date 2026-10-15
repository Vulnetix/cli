import logging

logger = logging.getLogger(__name__)


def login(request):
    logger.info("login from %s", request.headers.get("User-Agent"))
    logger.info("path %s method %s", request.path, request.method)
    logger.debug("content length %d", len(request.body))
    logger.info("keys: %s", list(request.POST.keys()))
    return render(request, "login.html", {"headers": request.headers})
