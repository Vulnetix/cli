from functools import wraps
from flask import request, abort


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
~>        if token:
            return f(*args, **kwargs)
        abort(401)
    return decorated
