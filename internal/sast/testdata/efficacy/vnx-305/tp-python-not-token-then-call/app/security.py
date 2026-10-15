from functools import wraps
from flask import request, jsonify


def api_key_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        api_key = request.args.get("api_key")
        if not api_key:
            return jsonify({"error": "missing key"}), 401
~>        return view(*args, **kwargs)
    return wrapper
