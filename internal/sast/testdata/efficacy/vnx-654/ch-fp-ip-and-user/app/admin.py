from flask import abort, request
from flask_login import current_user

ADMIN_NETS = ("10.0.0.",)


def admin_gate():
    if request.remote_addr.startswith(ADMIN_NETS) and current_user.is_authenticated:
        return True
    if request.remote_addr == "127.0.0.1":
        app.logger.debug("local request from %s", request.remote_addr)
    abort(403)
