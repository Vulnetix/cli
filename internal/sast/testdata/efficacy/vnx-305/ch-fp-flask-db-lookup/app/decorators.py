from functools import wraps
from flask import request, abort, g
from .models import ApiToken


def token_required(fn):
    @wraps(fn)
    def inner(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            abort(401)
        record = ApiToken.query.filter_by(value=token, revoked=False).first()
        if record is None:
            abort(403)
        g.user = record.user
        return fn(*args, **kwargs)
    return inner
