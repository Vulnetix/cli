from flask import Blueprint, abort, request
from flask_login import current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash

from .db import db

bp = Blueprint("account", __name__)


@bp.post("/account/change-password")
@login_required
def change_password():
    old = request.form.get("old_password", "")
    new = request.form.get("new_password", "")
    if not check_password_hash(current_user.password_hash, old):
        abort(403)
    current_user.password_hash = generate_password_hash(new)
    db.session.commit()
    return "", 204
