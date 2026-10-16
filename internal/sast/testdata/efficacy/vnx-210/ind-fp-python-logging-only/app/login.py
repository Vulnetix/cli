import logging

from flask import abort

log = logging.getLogger(__name__)


def login(username, password):
    user = find_user(username)
    if user is None or not user.check_password(password):
        log.info("failed login for %s", username)
        abort(401, "invalid username or password")
    return user
