import logging
import time

from flask import request

log = logging.getLogger(__name__)


def audit_login(user):
    client = request.remote_addr
    log.info("login user=%s ip=%s at=%s", user.id, client, time.time())
    db.audit.insert(user_id=user.id, ip=client, login_time=time.time())
