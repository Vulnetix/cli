from functools import wraps

from flask import abort, request

ALLOWED_NETS = {"10.0.0.5", "10.0.0.6"}


def internal_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
~>        if request.remote_addr in ALLOWED_NETS:
            return f(*args, **kwargs)
        abort(403)
    return wrapper
