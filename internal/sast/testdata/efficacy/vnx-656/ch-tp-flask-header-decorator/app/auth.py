from functools import wraps

from flask import request, abort


def maintenance_override(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
~>        if request.headers.get("X-Maintenance-Key") == "s3cr3t-override-77":
            return f(*args, **kwargs)
        abort(401)
    return wrapper
