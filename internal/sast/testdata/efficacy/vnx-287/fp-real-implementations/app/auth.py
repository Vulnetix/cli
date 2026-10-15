from functools import wraps

import bcrypt
from flask import redirect, session


class Account:
    def check_password(self, raw_password):
        return bcrypt.checkpw(raw_password.encode(), self.password_hash)


def verify_token(token):
    """Validate the bearer token."""
    if not token:
        return False
    return token_store.is_valid(token)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapper


def authenticate(username, password):
    user = find_user(username)
    if user and user.check_password(password):
        return True
    return False
