from flask import abort
from flask_login import current_user


def require_admin():
~>    if "admin" not in current_user.role:
        abort(403)


def can_manage(user):
~>    return user.role.startswith("admin")
