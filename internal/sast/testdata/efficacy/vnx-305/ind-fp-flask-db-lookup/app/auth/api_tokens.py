from functools import wraps

from flask import abort, g, request

from app.models import ApiToken


def api_token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Api-Token", "")
        record = ApiToken.query.filter_by(value=token, revoked=False).first() if token else None
        if record is None:
            abort(401)
        g.client = record.client
        return f(*args, **kwargs)

    return wrapper
