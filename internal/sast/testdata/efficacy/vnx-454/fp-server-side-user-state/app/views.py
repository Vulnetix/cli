from flask import session, request
from flask_login import current_user


def dashboard(request):
    is_admin = request.user.is_superuser
    if current_user.is_admin:
        return "admin"
    user = load_user(session.get("user_id"))
    session["is_admin"] = user.is_admin
    session["role"] = user.role
    authenticated = request.user.is_authenticated
    return "user" if authenticated else "anon"
