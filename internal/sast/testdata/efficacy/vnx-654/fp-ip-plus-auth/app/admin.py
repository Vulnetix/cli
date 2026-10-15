from flask import abort, request
from flask_login import current_user


def admin_gate(f):
    def wrapper(*args, **kwargs):
        if request.remote_addr in ALLOWED and current_user.is_authenticated:
            return f(*args, **kwargs)
        abort(403)
    return wrapper
