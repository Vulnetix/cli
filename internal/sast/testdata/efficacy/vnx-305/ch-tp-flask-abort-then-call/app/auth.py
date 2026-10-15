from functools import wraps
from flask import request, abort


def api_key_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-API-Key")
        if key is None:
            abort(401)
~>        return view(*args, **kwargs)
    return wrapper
