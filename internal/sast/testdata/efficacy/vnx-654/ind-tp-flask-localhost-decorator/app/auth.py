from functools import wraps
from flask import request, abort


def internal_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
~>        if request.remote_addr == "127.0.0.1":
            return f(*args, **kwargs)
        abort(403)
    return wrapper
