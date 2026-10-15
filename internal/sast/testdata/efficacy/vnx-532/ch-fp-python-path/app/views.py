import logging

logger = logging.getLogger(__name__)


def index(request):
    logger.info("path=%s method=%s", request.path, request.method)
    logger.info("ua=%s", request.headers.get("User-Agent"))
    logger.debug("body size=%d", len(request.body))
    return render(request, "index.html", {"headers": request.headers})
