import logging

LAST_LOOKUP = None
logger = logging.getLogger(__name__)


def remember(name):
    globals()["LAST_LOOKUP"] = name
    logger.info("stored %s", name)


HANDLERS = {"a": print}


def dispatch(request):
    handler = HANDLERS.get(request.args["action"])
    return handler
