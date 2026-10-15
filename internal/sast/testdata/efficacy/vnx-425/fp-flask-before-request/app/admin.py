from flask import Blueprint, abort
from flask_login import current_user

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.before_request
def guard():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)


@bp.route("/admin/users")
def users():
    return "users"
