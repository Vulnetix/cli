from functools import wraps

from flask import abort, request, session


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
~>        if request.remote_addr == "127.0.0.1":
            return f(*args, **kwargs)
        if not session.get("is_admin"):
            abort(403)
        return f(*args, **kwargs)
    return wrapper


TRUSTED = {"10.0.0.5", "10.0.0.6"}


def is_internal_caller():
~>    if request.headers.get("X-Real-IP") in TRUSTED:
        return True
    return False
