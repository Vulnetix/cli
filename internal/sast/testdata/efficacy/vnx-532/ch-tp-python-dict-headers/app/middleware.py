import logging

logger = logging.getLogger(__name__)


class AuditMiddleware:
    def __call__(self, request):
~>        logger.info("incoming headers: %s", dict(request.headers))
~>        logger.debug(f"payload={request.get_json()}")
        return self.get_response(request)
