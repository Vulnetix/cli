import logging

from flask import request

logger = logging.getLogger(__name__)


def search():
    logger.info("query %r", request.args.get("q"))
    page = int(request.args.get("page", "1"))
    logger.info("page %d", page)
    logger.info("path %s", request.path)
    term = request.args.get("q", "").replace("\r", "").replace("\n", "")
    logger.info("normalised term %s", term)
    return "ok"
