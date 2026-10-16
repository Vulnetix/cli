import logging

from flask import request

log = logging.getLogger(__name__)


def record_login(user):
    forwarded = request.headers.get("X-Forwarded-For", "")
    log.info("login user=%s xff=%s remote=%s", user.id, forwarded, request.remote_addr)
    AuditEvent.create(user_id=user.id, forwarded_for=forwarded, remote=request.remote_addr)
