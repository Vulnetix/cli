from flask import request, session, abort
from flask_login import current_user


def delete_user(uid):
    if not current_user.is_admin or session.get("role") != "admin":
        abort(403)
    role = request.form.get("role")
    users.update(uid, requested_role=role)
