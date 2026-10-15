import logging

log = logging.getLogger(__name__)


def audit(request):
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded is None:
        forwarded = request.META.get('REMOTE_ADDR')
    if forwarded == "":
        forwarded = "unknown"
    log.info("request from %s", forwarded)
    if not request.headers.get("X-Real-IP"):
        log.debug("no proxy header")
    return forwarded.split(",")[0]
