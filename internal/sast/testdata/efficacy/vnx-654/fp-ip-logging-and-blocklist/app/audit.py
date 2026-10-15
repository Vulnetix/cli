import logging

from flask import abort, request

BLOCKED = {"203.0.113.9"}
log = logging.getLogger(__name__)


def before():
    log.info("request from %s", request.remote_addr)
    if request.remote_addr in BLOCKED:
        abort(403)


def region():
    if request.remote_addr.startswith("10."):
        return "internal"
    return "external"
