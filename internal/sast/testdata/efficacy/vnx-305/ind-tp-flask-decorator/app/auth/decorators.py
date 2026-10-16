from functools import wraps

from flask import jsonify, request


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Access-Token")
~>        if token:
            return f(*args, **kwargs)
        return jsonify({"message": "Token is missing"}), 401

    return decorated
