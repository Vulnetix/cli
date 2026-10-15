from functools import wraps
from flask import request, abort

from .models import ApiToken


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if token and ApiToken.query.filter_by(value=token).first():
            return f(*args, **kwargs)
        abort(401)
    return decorated


def other(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = verify_token(request.headers.get("Authorization"))
        if token:
            return f(*args, **kwargs)
        abort(401)
    return decorated
