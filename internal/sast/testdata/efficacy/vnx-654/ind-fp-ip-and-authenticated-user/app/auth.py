from functools import wraps
from flask import request, abort
from flask_login import current_user

ALLOWED = {"10.0.0.5", "10.0.0.6"}


def restricted(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.remote_addr in ALLOWED and current_user.is_authenticated:
            return f(*args, **kwargs)
        abort(403)
    return wrapper
