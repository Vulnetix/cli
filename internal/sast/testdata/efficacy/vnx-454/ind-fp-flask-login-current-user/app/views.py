from flask import g, session
from flask_login import current_user

from .models import User


def load_permissions():
    user = User.query.get(session.get("user_id"))
    g.is_admin = current_user.is_admin
    is_admin = user is not None and user.role == "admin"
    return is_admin
